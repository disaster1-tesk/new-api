package service

// AccessTokenStaticMinRole returns the minimum built-in role of a static
// access token resource.
func AccessTokenStaticMinRole(resource string) (int, bool) {
	for _, static := range accessTokenStaticResources {
		if static.Resource == resource {
			return static.minRole, true
		}
	}
	return 0, false
}
