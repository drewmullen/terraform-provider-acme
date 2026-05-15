package acme

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// frameworkProvider is the Framework-side provider. It mirrors the server_url
// schema from the SDK provider so the mux server sees consistent schemas.
// Only acme_certificate lives here; acme_registration stays on SDK v2.
type frameworkProvider struct{}

var _ provider.Provider = (*frameworkProvider)(nil)

func NewFrameworkProvider() provider.Provider { return &frameworkProvider{} }

func (p *frameworkProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "acme"
}

func (p *frameworkProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"server_url": schema.StringAttribute{
				Required: true,
			},
		},
	}
}

type frameworkProviderModel struct {
	ServerURL types.String `tfsdk:"server_url"`
}

func (p *frameworkProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var data frameworkProviderModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	cfg := &Config{ServerURL: data.ServerURL.ValueString()}
	resp.ResourceData = cfg
	resp.DataSourceData = cfg
}

func (p *frameworkProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewCertificateResource,
	}
}

func (p *frameworkProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return nil
}
