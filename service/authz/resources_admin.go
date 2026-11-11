package authz

// Admin resources. Strings must equal accessTokenStaticResources in
// service/access_token_scope.go (service cannot be imported here); the mirror
// test in service guards them.
const (
	ResourceUser       = "user"
	ResourceBilling    = "billing"
	ResourceModel      = "model"
	ResourceDeployment = "deployment"
	ResourceGroup      = "group"
	ResourceLog        = "log"
	ResourceRedemption = "redemption"
	ResourceOption     = "option"
	ResourcePlugin     = "plugin"
	ResourceOps        = "ops"
)

// LogRead gates reading other users' logs, tasks and dashboard data.
var LogRead = Permission{Resource: ResourceLog, Action: ActionRead}

func adminResource(resource, label string, adminDefault bool, view, edit string) ResourceDefinition {
	var roles []string
	if adminDefault {
		roles = []string{BuiltInRoleAdmin}
	}
	actions := []ActionDefinition{{Action: ActionRead, LabelKey: "View", DescriptionKey: view, DefaultRoles: roles}}
	if edit != "" {
		actions = append(actions, ActionDefinition{Action: ActionWrite, LabelKey: "Edit", DescriptionKey: edit, DefaultRoles: roles})
	}
	return ResourceDefinition{Resource: resource, LabelKey: label, Actions: actions}
}

func init() {
	RegisterResource(adminResource(ResourceUser, "Users", true,
		"View users, their sign-in bindings, and permission settings.",
		"Create, edit, disable, and delete users, and reset their security settings."))
	RegisterResource(adminResource(ResourceBilling, "Billing management", true,
		"View all top-up records, subscription plans, and user subscriptions.",
		"Complete top-up orders and manage subscription plans and user subscriptions."))
	RegisterResource(adminResource(ResourceModel, "Models", true,
		"View models and vendors, and preview upstream sync.",
		"Edit models and vendors, and sync them from upstream."))
	RegisterResource(adminResource(ResourceDeployment, "Deployments", true,
		"View deployments and price estimates.",
		"Create, edit, and delete deployments, and test connections."))
	RegisterResource(adminResource(ResourceLog, "Logs", true,
		"View all users' usage logs, statistics, and tasks.", ""))
	RegisterResource(adminResource(ResourceRedemption, "Redemption codes", true,
		"View redemption codes.",
		"Create, edit, and delete redemption codes."))
	RegisterResource(adminResource(ResourceGroup, "Groups", true,
		"View groups and prefill groups.",
		"Create, edit, and delete prefill groups."))
	RegisterResource(adminResource(ResourceOption, "System settings", false,
		"View system settings, custom OAuth providers, and price sync sources.",
		"Change system settings and custom OAuth providers, and sync prices."))
	// Not "Task plugins" as in the access token catalog: that reads the same as
	// the task_plugin resource ("Task Plugin") in the permission matrix.
	RegisterResource(adminResource(ResourcePlugin, "Task plugin management", false,
		"View installed task plugins and their settings.",
		"Install, configure, test, and remove task plugins."))
	RegisterResource(adminResource(ResourceOps, "Operations", false,
		"View performance, system tasks, and system information.",
		"Run and manage maintenance tasks and performance settings."))
}
