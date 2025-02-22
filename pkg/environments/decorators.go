package environments

const (
	// DecoratorUsers to append osquery user as result decorator
	DecoratorUsers = "SELECT username AS osquery_user FROM users WHERE uid = (SELECT uid FROM processes WHERE pid = (SELECT pid FROM osquery_info) LIMIT 1);"
	// DecoratorHostname to append hostnames as result decorator
	DecoratorHostname = "SELECT hostname, local_hostname FROM system_info;"
	// DecoratorLoggedInUser to append the first logged in user as result decorator
	DecoratorLoggedInUser = "SELECT user || ' (' || tty || ')' AS username FROM logged_in_users WHERE type = 'user' ORDER BY time LIMIT 1;"
	// DecoratorOsqueryVersionHash to append the osquery version and the configuration hash as result decorator
	DecoratorOsqueryVersionHash = "SELECT version AS osquery_version, config_hash FROM osquery_info WHERE config_valid = 1;"
	// DecoratorMD5Process to append the MD5 of the running osquery binary as result decorator
	DecoratorMD5Process = "SELECT md5 AS osquery_md5 FROM hash WHERE path = (SELECT path FROM processes WHERE pid = (SELECT pid FROM osquery_info));"
)
