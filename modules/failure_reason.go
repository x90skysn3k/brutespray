package modules

// attemptFailureReason converts a stable attempt status code into a concise,
// human-readable explanation suitable for terminal and JSON output.
//
// It intentionally does not accept raw errors or credential material so the
// resulting message is safe to include in normal output.
func attemptFailureReason(statusCode string, success, connected bool) string {
	if success && connected {
		return ""
	}

	switch statusCode {
	case "auth_failure":
		return "Authentication rejected by target"
	case "connection_failure":
		return "Unable to establish connection"
	case "unsupported_service":
		return "Service is not supported by BruteSpray"
	case "skipped_service":
		return "Attempt skipped"
	case "module_timeout":
		return "Protocol module timed out"
	case "module_panic_recovered":
		return "Protocol module encountered an internal error"
	}

	if connected {
		return "Authentication rejected by target"
	}
	return "Unable to establish connection"
}
