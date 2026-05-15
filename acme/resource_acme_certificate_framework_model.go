package acme

import "github.com/hashicorp/terraform-plugin-framework/types"

// certificateResourceModel is the tfsdk model for acme_certificate.
type certificateResourceModel struct {
	ID                          types.String `tfsdk:"id"`
	AccountKeyPEM               types.String `tfsdk:"account_key_pem"`
	CommonName                  types.String `tfsdk:"common_name"`
	SubjectAlternativeNames     types.Set    `tfsdk:"subject_alternative_names"`
	KeyType                     types.String `tfsdk:"key_type"`
	CertificateRequestPEM       types.String `tfsdk:"certificate_request_pem"`
	ValidityDays                types.Int64  `tfsdk:"validity_days"`
	MinDaysRemaining            types.Int64  `tfsdk:"min_days_remaining"`
	MinDaysDynamic              types.Bool   `tfsdk:"min_days_dynamic"`
	UseRenewalInfo              types.Bool   `tfsdk:"use_renewal_info"`
	RenewalInfoMaxSleep         types.Int64  `tfsdk:"renewal_info_max_sleep"`
	RenewalInfoIgnoreRetryAfter types.Bool   `tfsdk:"renewal_info_ignore_retry_after"`
	DNSChallenge                types.List   `tfsdk:"dns_challenge"`
	HTTPChallenge               types.List   `tfsdk:"http_challenge"`
	HTTPWebrootChallenge        types.List   `tfsdk:"http_webroot_challenge"`
	HTTPMemcachedChallenge      types.List   `tfsdk:"http_memcached_challenge"`
	HTTPS3Challenge             types.List   `tfsdk:"http_s3_challenge"`
	TLSChallenge                types.List   `tfsdk:"tls_challenge"`
	PreCheckDelay               types.Int64  `tfsdk:"pre_check_delay"`
	RecursiveNameservers        types.List   `tfsdk:"recursive_nameservers"`
	DisableCompletePropagation  types.Bool   `tfsdk:"disable_complete_propagation"`
	PropagationWait             types.Int64  `tfsdk:"propagation_wait"`
	MustStaple                  types.Bool   `tfsdk:"must_staple"`
	PreferredChain              types.String `tfsdk:"preferred_chain"`
	Profile                     types.String `tfsdk:"profile"`
	CertTimeout                 types.Int64  `tfsdk:"cert_timeout"`
	DeactivateAuthorizations    types.Bool   `tfsdk:"deactivate_authorizations"`
	CertificateURL              types.String `tfsdk:"certificate_url"`
	CertificateDomain           types.String `tfsdk:"certificate_domain"`
	PrivateKeyPEM               types.String `tfsdk:"private_key_pem"`
	CertificatePEM              types.String `tfsdk:"certificate_pem"`
	IssuerPEM                   types.String `tfsdk:"issuer_pem"`
	CertificateP12              types.String `tfsdk:"certificate_p12"`
	CertificateNotBefore        types.String `tfsdk:"certificate_not_before"`
	CertificateNotAfter         types.String `tfsdk:"certificate_not_after"`
	CertificateSerial           types.String `tfsdk:"certificate_serial"`
	CertificateP12Password      types.String `tfsdk:"certificate_p12_password"`
	RevokeCertificateOnDestroy  types.Bool   `tfsdk:"revoke_certificate_on_destroy"`
	RevokeCertificateReason     types.String `tfsdk:"revoke_certificate_reason"`
	RenewalInfoWindowStart      types.String `tfsdk:"renewal_info_window_start"`
	RenewalInfoWindowEnd        types.String `tfsdk:"renewal_info_window_end"`
	RenewalInfoWindowSelected   types.String `tfsdk:"renewal_info_window_selected"`
	RenewalInfoExplanationURL   types.String `tfsdk:"renewal_info_explanation_url"`
	RenewalInfoRetryAfter       types.String `tfsdk:"renewal_info_retry_after"`
}

type dnsChallengeModel struct {
	Provider types.String `tfsdk:"provider"`
	Config   types.Map    `tfsdk:"config"`
}

type httpChallengeModel struct {
	Port        types.Int64  `tfsdk:"port"`
	ProxyHeader types.String `tfsdk:"proxy_header"`
}

type httpWebrootChallengeModel struct {
	Directory types.String `tfsdk:"directory"`
}

type httpMemcachedChallengeModel struct {
	Hosts types.Set `tfsdk:"hosts"`
}

type httpS3ChallengeModel struct {
	S3Bucket types.String `tfsdk:"s3_bucket"`
}

type tlsChallengeModel struct {
	Port types.Int64 `tfsdk:"port"`
}

// readBoolField preserves null when the prior state had no value set.
// Boolean resource attributes are Optional-only (no Computed, no Default);
// if the user never set the field, we keep it null rather than materialising
// the API/SDK default, which would cause a perpetual diff.
func readBoolField(priorState types.Bool, apiValue bool) types.Bool {
	if priorState.IsNull() {
		return types.BoolNull()
	}
	return types.BoolValue(apiValue)
}
