package acme

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"strconv"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/acme/api"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/challenge/tlsalpn01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/http/memcached"
	"github.com/go-acme/lego/v4/providers/http/s3"
	"github.com/go-acme/lego/v4/providers/http/webroot"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/vancluever/terraform-provider-acme/v2/acme/dnsplugin"
)

type certificateResource struct {
	cfg *Config
}

var _ resource.Resource = (*certificateResource)(nil)
var _ resource.ResourceWithConfigure = (*certificateResource)(nil)
var _ resource.ResourceWithUpgradeState = (*certificateResource)(nil)
var _ resource.ResourceWithModifyPlan = (*certificateResource)(nil)
var _ resource.ResourceWithValidateConfig = (*certificateResource)(nil)

func NewCertificateResource() resource.Resource { return &certificateResource{} }

func (r *certificateResource) Metadata(_ context.Context, _ resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = "acme_certificate"
}

func (r *certificateResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	cfg, ok := req.ProviderData.(*Config)
	if !ok {
		resp.Diagnostics.AddError("unexpected provider data type", fmt.Sprintf("got %T", req.ProviderData))
		return
	}
	r.cfg = cfg
}

// ─── UpgradeState (SDK v2 V5 → Framework V6) ─────────────────────────────────

func (r *certificateResource) UpgradeState(ctx context.Context) map[int64]resource.StateUpgrader {
	schemaResp := &resource.SchemaResponse{}
	r.Schema(ctx, resource.SchemaRequest{}, schemaResp)
	return map[int64]resource.StateUpgrader{
		5: {
			PriorSchema: &schemaResp.Schema,
			StateUpgrader: func(ctx context.Context, req resource.UpgradeStateRequest, resp *resource.UpgradeStateResponse) {
				var data certificateResourceModel
				resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
				resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
			},
		},
	}
}

// ─── ModifyPlan (renewal detection) ──────────────────────────────────────────

func (r *certificateResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.State.Raw.IsNull() || req.Plan.Raw.IsNull() {
		return
	}

	var state, plan certificateResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var dnsChallenges []dnsChallengeModel
	resp.Diagnostics.Append(plan.DNSChallenge.ElementsAs(ctx, &dnsChallenges, false)...)
	seen := map[string]bool{}
	for _, c := range dnsChallenges {
		p := c.Provider.ValueString()
		if seen[p] {
			resp.Diagnostics.AddError("duplicate dns_challenge providers", p)
			return
		}
		seen[p] = true
	}

	// When only the P12 password changes (no renewal), the P12 blob will be
	// regenerated with the new password, so mark it unknown.
	if !state.CertificateP12Password.Equal(plan.CertificateP12Password) {
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root("certificate_p12"), types.StringUnknown())...)
	}

	// Use plan's config values for the renewal check (e.g. new max_sleep),
	// but keep state's ARI window data so we check against the stored window.
	checkState := state
	checkState.UseRenewalInfo = plan.UseRenewalInfo
	checkState.RenewalInfoMaxSleep = plan.RenewalInfoMaxSleep
	checkState.MinDaysRemaining = plan.MinDaysRemaining
	checkState.MinDaysDynamic = plan.MinDaysDynamic
	shouldRenew, err := r.fwShouldRenew(&checkState, time.Now())
	if err != nil {
		resp.Diagnostics.AddError("error checking renewal", err.Error())
		return
	}

	validityChanged := !state.ValidityDays.Equal(plan.ValidityDays)
	useRenewalInfoChanged := !state.UseRenewalInfo.Equal(plan.UseRenewalInfo)

	// Mark ARI fields unknown when use_renewal_info changes (stale state data)
	// or when renewal is happening (all cert outputs will be replaced).
	if shouldRenew || validityChanged || useRenewalInfoChanged {
		unknownStr := types.StringUnknown()
		for _, attr := range []string{
			"renewal_info_window_start", "renewal_info_window_end",
			"renewal_info_window_selected", "renewal_info_explanation_url", "renewal_info_retry_after",
		} {
			resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root(attr), unknownStr)...)
		}
	}

	if !shouldRenew && !validityChanged {
		return
	}

	unknownStr := types.StringUnknown()
	for _, attr := range []string{
		"certificate_pem", "certificate_p12", "certificate_url", "certificate_domain",
		"certificate_not_before", "certificate_not_after", "private_key_pem", "issuer_pem",
		"certificate_serial",
	} {
		resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root(attr), unknownStr)...)
	}
}

func (r *certificateResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var data certificateResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// AtLeastOneOf: common_name, subject_alternative_names, certificate_request_pem
	if data.CommonName.IsNull() && (data.SubjectAlternativeNames.IsNull() || len(data.SubjectAlternativeNames.Elements()) == 0) && data.CertificateRequestPEM.IsNull() {
		resp.Diagnostics.AddAttributeError(
			path.Root("subject_alternative_names"),
			"Missing required field",
			"\"subject_alternative_names\": one of\n`certificate_request_pem,common_name,subject_alternative_names` must be\nspecified",
		)
	}

	// validity_days must not fall within min_days_remaining (would trigger renewal on every apply)
	if !data.ValidityDays.IsNull() && !data.ValidityDays.IsUnknown() && !fwBool(data.MinDaysDynamic) {
		days := data.ValidityDays.ValueInt64()
		minDays := fwInt64(data.MinDaysRemaining, 30)
		if days <= minDays {
			resp.Diagnostics.AddAttributeError(
				path.Root("validity_days"),
				"Invalid validity_days",
				fmt.Sprintf(
					"validity_days (%d day(s)) is within min_days_remaining (%d); "+
						"this would trigger immediate renewal on every apply - "+
						"reduce min_days_remaining or increase validity_days",
					days, minDays,
				),
			)
		}
	}
}

// ─── CRUD ─────────────────────────────────────────────────────────────────────

func (r *certificateResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data certificateResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resourceUUID, err := uuid.GenerateUUID()
	if err != nil {
		resp.Diagnostics.AddError("UUID generation failed", err.Error())
		return
	}

	client, diags := r.fwExpandACMEClient(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	dnsCloser, diags := r.fwSetChallengeProviders(ctx, client, &data)
	defer dnsCloser()
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	cert, err := r.fwObtainCertificate(ctx, client, &data)
	if err != nil {
		resp.Diagnostics.AddError("error creating certificate", err.Error())
		return
	}

	data.ID = types.StringValue(resourceUUID)
	resp.Diagnostics.Append(r.fwSaveCertificate(&data, cert)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(r.fwRefreshRenewalInfo(&data, client, time.Now())...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *certificateResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data certificateResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if data.CertificatePEM.ValueString() == "" {
		client, diags := r.fwExpandACMEClient(ctx, &data)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		srcCR, err := client.Certificate.Get(data.CertificateURL.ValueString(), true)
		if err != nil {
			resp.Diagnostics.AddError("error reading certificate", err.Error())
			return
		}
		cert := r.fwExpandCertificateResource(&data)
		cert.Certificate = srcCR.Certificate
		resp.Diagnostics.Append(r.fwSaveCertificate(&data, cert)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	client, diags := r.fwExpandACMEClient(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(r.fwRefreshRenewalInfo(&data, client, time.Now())...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *certificateResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state certificateResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Use plan config values for renewal check (e.g. updated max_sleep or use_renewal_info)
	// but keep state's ARI window data for the shouldRenew decision.
	checkState := state
	checkState.UseRenewalInfo = plan.UseRenewalInfo
	checkState.RenewalInfoMaxSleep = plan.RenewalInfoMaxSleep
	checkState.MinDaysRemaining = plan.MinDaysRemaining
	checkState.MinDaysDynamic = plan.MinDaysDynamic
	shouldRenew, err := r.fwShouldRenew(&checkState, time.Now())
	if err != nil {
		resp.Diagnostics.AddError("error checking renewal", err.Error())
		return
	}

	validityChanged := !state.ValidityDays.Equal(plan.ValidityDays)
	if !shouldRenew && !validityChanged {
		if !state.CertificateP12Password.Equal(plan.CertificateP12Password) {
			cert := r.fwExpandCertificateResource(&state)
			plan.ID = state.ID
			resp.Diagnostics.Append(r.fwSaveCertificate(&plan, cert)...)
		} else {
			// No renewal and no p12 change: preserve cert outputs from state
			// but keep all config values from plan (they may have changed).
			plan.ID = state.ID
			plan.CertificateURL = state.CertificateURL
			plan.CertificateDomain = state.CertificateDomain
			plan.PrivateKeyPEM = state.PrivateKeyPEM
			plan.CertificatePEM = state.CertificatePEM
			plan.IssuerPEM = state.IssuerPEM
			plan.CertificateP12 = state.CertificateP12
			plan.CertificateNotBefore = state.CertificateNotBefore
			plan.CertificateNotAfter = state.CertificateNotAfter
			plan.CertificateSerial = state.CertificateSerial
			// ARI fields will be refreshed below; initialize to state values
			// so they're known even if the refresh is skipped.
			plan.RenewalInfoWindowStart = state.RenewalInfoWindowStart
			plan.RenewalInfoWindowEnd = state.RenewalInfoWindowEnd
			plan.RenewalInfoWindowSelected = state.RenewalInfoWindowSelected
			plan.RenewalInfoExplanationURL = state.RenewalInfoExplanationURL
			plan.RenewalInfoRetryAfter = state.RenewalInfoRetryAfter
		}
		// Refresh ARI data when use_renewal_info changes direction so the next
		// plan has up-to-date window data for shouldRenew decisions.
		if !state.UseRenewalInfo.Equal(plan.UseRenewalInfo) {
			ariClient, ariDiags := r.fwExpandACMEClient(ctx, &plan)
			if !ariDiags.HasError() {
				resp.Diagnostics.Append(r.fwRefreshRenewalInfo(&plan, ariClient, time.Now())...)
			}
		}
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		return
	}

	// Use plan's use_renewal_info flag but state's ARI window (plan has it as unknown).
	sleepData := state
	sleepData.UseRenewalInfo = plan.UseRenewalInfo
	if err := r.fwSleepUntilRenewalTime(&sleepData); err != nil {
		resp.Diagnostics.AddError("error waiting for renewal window", err.Error())
		return
	}

	client, diags := r.fwExpandACMEClient(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	cert := r.fwExpandCertificateResource(&state)

	dnsCloser, diags := r.fwSetChallengeProviders(ctx, client, &plan)
	defer dnsCloser()
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var notAfter time.Time
	if !plan.ValidityDays.IsNull() {
		notAfter = time.Now().Add(time.Duration(plan.ValidityDays.ValueInt64())*24*time.Hour + time.Minute*15)
	}

	newCert, err := renewWithOptions(
		client.Certificate,
		*cert,
		localRenewOptions{
			RenewOptions: certificate.RenewOptions{
				NotAfter:                       notAfter,
				Bundle:                         true,
				PreferredChain:                 plan.PreferredChain.ValueString(),
				Profile:                        plan.Profile.ValueString(),
				MustStaple:                     fwBool(plan.MustStaple),
				AlwaysDeactivateAuthorizations: fwBool(plan.DeactivateAuthorizations),
			},
			UseARI: fwBool(plan.UseRenewalInfo),
		},
	)
	if err != nil {
		resp.Diagnostics.AddError("error renewing certificate", err.Error())
		return
	}

	plan.ID = state.ID
	resp.Diagnostics.Append(r.fwSaveCertificate(&plan, newCert)...)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.RenewalInfoWindowStart = types.StringValue("")
	plan.RenewalInfoWindowEnd = types.StringValue("")
	plan.RenewalInfoWindowSelected = types.StringValue("")
	plan.RenewalInfoExplanationURL = types.StringValue("")
	plan.RenewalInfoRetryAfter = types.StringValue("")

	resp.Diagnostics.Append(r.fwRefreshRenewalInfo(&plan, client, time.Now())...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *certificateResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data certificateResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// null means not explicitly set; match SDK v2 Default: true behavior.
	if data.RevokeCertificateOnDestroy.ValueBool() == false && !data.RevokeCertificateOnDestroy.IsNull() {
		return
	}

	client, diags := r.fwExpandACMEClient(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	cert := r.fwExpandCertificateResource(&data)
	remaining, err := certSecondsRemaining(cert, time.Now())
	if err != nil {
		resp.Diagnostics.AddError("error checking certificate expiry", err.Error())
		return
	}
	if remaining < 0 {
		return
	}

	if reason := data.RevokeCertificateReason.ValueString(); reason != "" {
		reasonNum, err := GetRevocationReason(RevocationReason(reason))
		if err != nil {
			resp.Diagnostics.AddError("invalid revocation reason", err.Error())
			return
		}
		if err := client.Certificate.RevokeWithReason(cert.Certificate, &reasonNum); err != nil {
			resp.Diagnostics.AddError("error revoking certificate", err.Error())
		}
	} else {
		if err := client.Certificate.Revoke(cert.Certificate); err != nil {
			resp.Diagnostics.AddError("error revoking certificate", err.Error())
		}
	}
}

// ─── ACME helpers ─────────────────────────────────────────────────────────────

func (r *certificateResource) fwExpandACMEClient(_ context.Context, data *certificateResourceModel) (*lego.Client, diag.Diagnostics) {
	var diags diag.Diagnostics

	key, err := privateKeyFromPEM([]byte(data.AccountKeyPEM.ValueString()))
	if err != nil {
		diags.AddError("error parsing account key", err.Error())
		return nil, diags
	}
	user := &acmeUser{key: key}

	config := lego.NewConfig(user)
	config.CADirURL = r.cfg.ServerURL
	if !data.KeyType.IsNull() && !data.KeyType.IsUnknown() {
		config.Certificate.KeyType = certcrypto.KeyType(data.KeyType.ValueString())
	}
	if !data.CertTimeout.IsNull() {
		config.Certificate.Timeout = time.Second * time.Duration(data.CertTimeout.ValueInt64())
	}

	client, err := lego.NewClient(config)
	if err != nil {
		diags.AddError("error creating ACME client", err.Error())
		return nil, diags
	}
	user.Registration, err = client.Registration.ResolveAccountByKey()
	if err != nil {
		diags.AddError("error resolving ACME account", err.Error())
		return nil, diags
	}
	return client, diags
}

func (r *certificateResource) fwSetChallengeProviders(ctx context.Context, client *lego.Client, data *certificateResourceModel) (func(), diag.Diagnostics) {
	var diags diag.Diagnostics
	noop := func() {}

	nameservers := fwListStrings(ctx, data.RecursiveNameservers)

	if len(data.DNSChallenge.Elements()) > 0 {
		var challenges []dnsChallengeModel
		diags.Append(data.DNSChallenge.ElementsAs(ctx, &challenges, false)...)
		if diags.HasError() {
			return noop, diags
		}

		var dnsClosers []func()
		wrapper, _ := NewDNSProviderWrapper()
		var isSequential bool
		var sequentialInterval time.Duration

		for _, c := range challenges {
			cfg := map[string]string{}
			if !c.Config.IsNull() {
				diags.Append(c.Config.ElementsAs(ctx, &cfg, false)...)
				if diags.HasError() {
					return noop, diags
				}
			}
			result, err := dnsplugin.NewClient(c.Provider.ValueString(), cfg, nameservers)
			if err != nil {
				diags.AddError("DNS challenge provider error", err.Error())
				return noop, diags
			}
			wrapper.providers = append(wrapper.providers, result.Provider)
			dnsClosers = append(dnsClosers, result.Closer)
			if result.IsSequential {
				isSequential = true
			}
			if result.SequentialInterval > sequentialInterval {
				sequentialInterval = result.SequentialInterval
			}
		}

		closer := func() {
			for _, f := range dnsClosers {
				f()
			}
		}

		var p challenge.Provider
		if isSequential {
			p = wrapper.ToSequential(sequentialInterval)
		} else {
			p = wrapper
		}

		opts := r.fwDNSOptions(data)
		if err := client.Challenge.SetDNS01Provider(p, opts...); err != nil {
			diags.AddError("error setting DNS01 provider", err.Error())
			return noop, diags
		}
		return closer, diags
	}

	if len(data.HTTPChallenge.Elements()) > 0 {
		var challenges []httpChallengeModel
		diags.Append(data.HTTPChallenge.ElementsAs(ctx, &challenges, false)...)
		if diags.HasError() {
			return noop, diags
		}
		c := challenges[0]
		p := http01.NewProviderServer("", strconv.FormatInt(c.Port.ValueInt64(), 10))
		if !c.ProxyHeader.IsNull() {
			p.SetProxyHeader(c.ProxyHeader.ValueString())
		}
		if err := client.Challenge.SetHTTP01Provider(p); err != nil {
			diags.AddError("error setting HTTP01 provider", err.Error())
		}
		return noop, diags
	}

	if len(data.HTTPWebrootChallenge.Elements()) > 0 {
		var challenges []httpWebrootChallengeModel
		diags.Append(data.HTTPWebrootChallenge.ElementsAs(ctx, &challenges, false)...)
		if diags.HasError() {
			return noop, diags
		}
		p, err := webroot.NewHTTPProvider(challenges[0].Directory.ValueString())
		if err != nil {
			diags.AddError("error creating webroot provider", err.Error())
			return noop, diags
		}
		if err := client.Challenge.SetHTTP01Provider(p); err != nil {
			diags.AddError("error setting HTTP01 provider", err.Error())
		}
		return noop, diags
	}

	if len(data.HTTPMemcachedChallenge.Elements()) > 0 {
		var challenges []httpMemcachedChallengeModel
		diags.Append(data.HTTPMemcachedChallenge.ElementsAs(ctx, &challenges, false)...)
		if diags.HasError() {
			return noop, diags
		}
		var hosts []string
		diags.Append(challenges[0].Hosts.ElementsAs(ctx, &hosts, false)...)
		if diags.HasError() {
			return noop, diags
		}
		p, err := memcached.NewMemcachedProvider(hosts)
		if err != nil {
			diags.AddError("error creating memcached provider", err.Error())
			return noop, diags
		}
		if err := client.Challenge.SetHTTP01Provider(p); err != nil {
			diags.AddError("error setting HTTP01 provider", err.Error())
		}
		return noop, diags
	}

	if len(data.HTTPS3Challenge.Elements()) > 0 {
		var challenges []httpS3ChallengeModel
		diags.Append(data.HTTPS3Challenge.ElementsAs(ctx, &challenges, false)...)
		if diags.HasError() {
			return noop, diags
		}
		p, err := s3.NewHTTPProvider(challenges[0].S3Bucket.ValueString())
		if err != nil {
			diags.AddError("error creating S3 provider", err.Error())
			return noop, diags
		}
		if err := client.Challenge.SetHTTP01Provider(p); err != nil {
			diags.AddError("error setting HTTP01 provider", err.Error())
		}
		return noop, diags
	}

	if len(data.TLSChallenge.Elements()) > 0 {
		var challenges []tlsChallengeModel
		diags.Append(data.TLSChallenge.ElementsAs(ctx, &challenges, false)...)
		if diags.HasError() {
			return noop, diags
		}
		p := tlsalpn01.NewProviderServer("", strconv.FormatInt(challenges[0].Port.ValueInt64(), 10))
		if err := client.Challenge.SetTLSALPN01Provider(p); err != nil {
			diags.AddError("error setting TLSALPN01 provider", err.Error())
		}
		return noop, diags
	}

	return noop, diags
}

func (r *certificateResource) fwDNSOptions(data *certificateResourceModel) []dns01.ChallengeOption {
	var opts []dns01.ChallengeOption
	if fwBool(data.DisableCompletePropagation) {
		opts = append(opts, dns01.DisableCompletePropagationRequirement())
	}
	if !data.PropagationWait.IsNull() && data.PropagationWait.ValueInt64() > 0 {
		opts = append(opts, dns01.PropagationWait(time.Duration(data.PropagationWait.ValueInt64())*time.Second, true))
	}
	if !data.PreCheckDelay.IsNull() && data.PreCheckDelay.ValueInt64() > 0 {
		opts = append(opts, dns01.WrapPreCheck(resourceACMECertificatePreCheckDelay(int(data.PreCheckDelay.ValueInt64()))))
	}
	return opts
}

func (r *certificateResource) fwObtainCertificate(ctx context.Context, client *lego.Client, data *certificateResourceModel) (*certificate.Resource, error) {
	var notAfter time.Time
	if !data.ValidityDays.IsNull() {
		notAfter = time.Now().Add(time.Duration(data.ValidityDays.ValueInt64())*24*time.Hour + time.Minute*15)
	}

	if !data.CertificateRequestPEM.IsNull() && data.CertificateRequestPEM.ValueString() != "" {
		csr, err := csrFromPEM([]byte(data.CertificateRequestPEM.ValueString()))
		if err != nil {
			return nil, err
		}
		return client.Certificate.ObtainForCSR(certificate.ObtainForCSRRequest{
			CSR:                            csr,
			NotAfter:                       notAfter,
			Bundle:                         true,
			PreferredChain:                 data.PreferredChain.ValueString(),
			Profile:                        data.Profile.ValueString(),
			AlwaysDeactivateAuthorizations: fwBool(data.DeactivateAuthorizations),
		})
	}

	var domains []string
	cn := data.CommonName.ValueString()
	if cn != "" {
		domains = append(domains, cn)
	}
	var sans []string
	_ = data.SubjectAlternativeNames.ElementsAs(ctx, &sans, false)
	for _, s := range sans {
		if s != cn {
			domains = append(domains, s)
		}
	}

	return client.Certificate.Obtain(certificate.ObtainRequest{
		Domains:                        domains,
		NotAfter:                       notAfter,
		Bundle:                         true,
		MustStaple:                     fwBool(data.MustStaple),
		PreferredChain:                 data.PreferredChain.ValueString(),
		Profile:                        data.Profile.ValueString(),
		AlwaysDeactivateAuthorizations: fwBool(data.DeactivateAuthorizations),
	})
}

func (r *certificateResource) fwSaveCertificate(data *certificateResourceModel, cert *certificate.Resource) diag.Diagnostics {
	var diags diag.Diagnostics
	data.CertificateURL = types.StringValue(cert.CertURL)
	data.CertificateDomain = types.StringValue(cert.Domain)
	data.PrivateKeyPEM = types.StringValue(string(cert.PrivateKey))

	issued, notBefore, notAfter, serial, issuer, err := splitPEMBundle(cert.Certificate)
	if err != nil {
		diags.AddError("error parsing certificate bundle", err.Error())
		return diags
	}
	data.CertificatePEM = types.StringValue(string(issued))
	data.IssuerPEM = types.StringValue(string(issuer))
	data.CertificateNotBefore = types.StringValue(notBefore)
	data.CertificateNotAfter = types.StringValue(notAfter)
	data.CertificateSerial = types.StringValue(serial)

	if len(cert.PrivateKey) > 0 {
		pfxB64, err := bundleToPKCS12(cert.Certificate, cert.PrivateKey, data.CertificateP12Password.ValueString())
		if err != nil {
			diags.AddError("error building PKCS12", err.Error())
			return diags
		}
		data.CertificateP12 = types.StringValue(string(pfxB64))
	} else {
		data.CertificateP12 = types.StringValue("")
	}
	return diags
}

func (r *certificateResource) fwExpandCertificateResource(data *certificateResourceModel) *certificate.Resource {
	cert := &certificate.Resource{
		Domain:  data.CertificateDomain.ValueString(),
		CertURL: data.CertificateURL.ValueString(),
	}
	if pk := data.PrivateKeyPEM.ValueString(); pk != "" {
		cert.PrivateKey = []byte(pk)
	}
	if csr := data.CertificateRequestPEM.ValueString(); csr != "" {
		cert.CSR = []byte(csr)
	}
	certPEM := data.CertificatePEM.ValueString()
	issuerPEM := data.IssuerPEM.ValueString()
	if certPEM != "" {
		cert.Certificate = []byte(certPEM + issuerPEM)
	}
	return cert
}

// ─── ARI helpers (inlined from SDK v2 equivalents) ────────────────────────────

func (r *certificateResource) fwShouldRenew(data *certificateResourceModel, now time.Time) (bool, error) {
	if fwBool(data.UseRenewalInfo) {
		canSleep, err := r.fwRenewalInfoCanSleep(data, now)
		if err != nil {
			return false, err
		}
		if canSleep {
			return true, nil
		}
	}
	return r.fwHasExpired(data, now)
}

func (r *certificateResource) fwHasExpired(data *certificateResourceModel, now time.Time) (bool, error) {
	cert := r.fwExpandCertificateResource(data)
	remaining, err := certDaysRemaining(cert, now)
	if err != nil {
		return false, fmt.Errorf("unable to calculate time to certificate expiry: %w", err)
	}

	if fwBool(data.MinDaysDynamic) {
		lifetimeDays, err := certLifetimeDays(cert)
		if err != nil {
			return false, err
		}
		threshold := 1.0 / 3.0
		if lifetimeDays <= 10.0 {
			threshold = 0.5
		}
		return float64(remaining)/lifetimeDays <= threshold, nil
	}

	minDays := fwInt64(data.MinDaysRemaining, 30)
	if minDays < 0 {
		log.Printf("[WARN] min_days_remaining is negative, certificate will never be renewed")
		return false, nil
	}
	return minDays >= remaining, nil
}

func (r *certificateResource) fwRenewalInfoCanSleep(data *certificateResourceModel, now time.Time) (bool, error) {
	selected := data.RenewalInfoWindowSelected.ValueString()
	if selected == "" {
		return false, errors.New("renewal_info_window_selected expected to be set")
	}
	selectedTime, err := time.Parse(time.RFC3339, selected)
	if err != nil {
		return false, fmt.Errorf("malformed renewal_info_window_selected: %w", err)
	}
	maxSleep := fwInt64(data.RenewalInfoMaxSleep, 0)
	canSleepUntil := now.Add(time.Second * time.Duration(maxSleep))
	return !canSleepUntil.Before(selectedTime), nil
}

func (r *certificateResource) fwSleepUntilRenewalTime(data *certificateResourceModel) error {
	if !fwBool(data.UseRenewalInfo) {
		return nil
	}
	selected := data.RenewalInfoWindowSelected.ValueString()
	if selected == "" {
		return errors.New("renewal_info_window_selected expected to be set")
	}
	selectedTime, err := time.Parse(time.RFC3339, selected)
	if err != nil {
		return fmt.Errorf("malformed renewal_info_window_selected: %w", err)
	}
	sleepDuration := time.Until(selectedTime)
	log.Printf("[DEBUG] sleeping %s until renewal time: %s", sleepDuration.Truncate(time.Second), selectedTime)
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	done := make(chan bool)
	go func() {
		time.Sleep(sleepDuration)
		done <- true
	}()
	for {
		select {
		case <-done:
			return nil
		case <-ticker.C:
			log.Printf("[DEBUG] (%s remaining) sleeping until renewal time: %s",
				time.Until(selectedTime).Truncate(time.Second), selectedTime)
		}
	}
}

func (r *certificateResource) fwRefreshRenewalInfo(data *certificateResourceModel, client *lego.Client, now time.Time) diag.Diagnostics {
	var diags diag.Diagnostics

	// ARI data is always fetched regardless of use_renewal_info; the flag only
	// controls whether the renewal window influences renewal decisions.
	retryAfterStr := data.RenewalInfoRetryAfter.ValueString()
	if retryAfterStr != "" && !fwBool(data.RenewalInfoIgnoreRetryAfter) {
		retryAfter, err := time.Parse(time.RFC3339, retryAfterStr)
		if err != nil {
			diags.AddError("malformed renewal_info_retry_after", err.Error())
			return diags
		}
		if now.Before(retryAfter) {
			return diags
		}
	}

	cb, err := parsePEMBundle([]byte(data.CertificatePEM.ValueString()))
	if err != nil {
		diags.AddError("error parsing certificate for ARI", err.Error())
		return diags
	}
	if cb[0].IsCA {
		diags.AddError("error parsing certificate for ARI", "first certificate is a CA certificate")
		return diags
	}
	cert := cb[0]
	if now.After(cert.NotAfter) {
		log.Println("[WARN] certificate is expired, cannot retrieve ARI data")
		data.RenewalInfoWindowStart = types.StringValue("")
		data.RenewalInfoWindowEnd = types.StringValue("")
		data.RenewalInfoWindowSelected = types.StringValue("")
		data.RenewalInfoExplanationURL = types.StringValue("")
		data.RenewalInfoRetryAfter = types.StringValue("")
		return diags
	}

	renewalInfoResp, err := client.Certificate.GetRenewalInfo(certificate.RenewalInfoRequest{Cert: cert})
	if err != nil {
		if errors.Is(err, api.ErrNoARI) {
			log.Println("[WARN] ARI unsupported on this endpoint")
			data.RenewalInfoWindowStart = types.StringValue("")
			data.RenewalInfoWindowEnd = types.StringValue("")
			data.RenewalInfoWindowSelected = types.StringValue("")
			data.RenewalInfoExplanationURL = types.StringValue("")
			data.RenewalInfoRetryAfter = types.StringValue("")
			return diags
		}
		diags.AddError("error fetching renewal info", err.Error())
		return diags
	}

	windowStart := renewalInfoResp.SuggestedWindow.Start
	windowEnd := renewalInfoResp.SuggestedWindow.End
	windowSelected := windowStart
	if d := windowEnd.Sub(windowStart); d > 0 {
		windowSelected = windowSelected.Add(time.Duration(rand.Int63n(int64(d))))
	}

	data.RenewalInfoWindowStart = types.StringValue(windowStart.UTC().Format(time.RFC3339))
	data.RenewalInfoWindowEnd = types.StringValue(windowEnd.UTC().Format(time.RFC3339))
	data.RenewalInfoWindowSelected = types.StringValue(windowSelected.UTC().Format(time.RFC3339))
	data.RenewalInfoExplanationURL = types.StringValue(renewalInfoResp.ExplanationURL)
	data.RenewalInfoRetryAfter = types.StringValue(now.Add(renewalInfoResp.RetryAfter).UTC().Format(time.RFC3339))
	return diags
}

// ─── Tiny helpers ─────────────────────────────────────────────────────────────

// fwBool returns false for null/unknown booleans.
func fwBool(b types.Bool) bool {
	if b.IsNull() || b.IsUnknown() {
		return false
	}
	return b.ValueBool()
}

func fwInt64(v types.Int64, def int64) int64 {
	if v.IsNull() || v.IsUnknown() {
		return def
	}
	return v.ValueInt64()
}

func fwListStrings(ctx context.Context, l types.List) []string {
	if l.IsNull() || l.IsUnknown() {
		return nil
	}
	var out []string
	_ = l.ElementsAs(ctx, &out, false)
	return out
}

// suppress unused import
var _ = strings.Join
