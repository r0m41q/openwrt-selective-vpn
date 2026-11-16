BEGIN { FS = "\t" }
{
	# never return log text, even when a familiar message contains a secret
	if ($0 !~ /(^|[[:space:]])openvpn[^[:space:]]*\[[0-9]+\]: /) next
	message = $0
	sub(/^.*openvpn[^[:space:]]*\[[0-9]+\]: /, "", message)
	if (message ~ /AUTH_FAILED/) auth++
	if (message ~ /TLS Error:|VERIFY ERROR:|TLS handshake failed/) tls++
	if (message ~ /Connection refused|Connection reset|Network is unreachable|RESOLVE: Cannot resolve host address/) connection++
	if (message ~ /SIGUSR1.*restarting|SIGTERM.*exiting/) restart++
}
END {
	print "logs.authentication_failure\t" auth + 0
	print "logs.tls_failure\t" tls + 0
	print "logs.connection_failure\t" connection + 0
	print "logs.restart\t" restart + 0
}
