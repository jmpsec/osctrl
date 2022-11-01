package users

// Helper to compare two set of permissions
func SameAccess(acc1, acc2 EnvAccess) bool {
	return (acc1.Admin == acc2.Admin) && (acc1.Query == acc2.Query) && (acc1.Carve == acc2.Carve) && (acc1.User == acc2.User)
}

// Helper to convert received permissions into struct
func GenEnvAccess(admin, carve, query, user bool) EnvAccess {
	if admin {
		return EnvAccess{
			User:  true,
			Query: true,
			Carve: true,
			Admin: true,
		}
	}
	return EnvAccess{
		User:  user,
		Query: query,
		Carve: carve,
		Admin: admin,
	}
}
