package config

const DefaultConfig = `
title = "gitleaks config"

[[rules]]
	description = "AWS Secret Key"
	regex = '''(?i)aws(.{0,20})?(?-i)['\"][0-9a-zA-Z\/+]{40}['\"]'''
	tags = ["key", "AWS"]

[[rules]]
	description = "AWS MWS key"
	regex = '''amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'''
	tags = ["key", "AWS", "MWS"]

[[rules]]
	description = "Facebook Secret Key"
	regex = '''(?i)(facebook|fb)(.{0,20})?(?-i)['\"][0-9a-f]{32}['\"]'''
	tags = ["key", "Facebook"]

[[rules]]
	description = "Facebook Client ID"
	regex = '''(?i)(facebook|fb)(.{0,20})?['\"][0-9]{13,17}['\"]'''
	tags = ["key", "Facebook"]

[[rules]]
	description = "Twitter Secret Key"
	regex = '''(?i)twitter(.{0,20})?['\"][0-9a-z]{35,44}['\"]'''
	tags = ["key", "Twitter"]

[[rules]]
	description = "Twitter Client ID"
	regex = '''(?i)twitter(.{0,20})?['\"][0-9a-z]{18,25}['\"]'''
	tags = ["client", "Twitter"]

[[rules]]
	description = "Github"
	regex = '''(?i)github(.{0,20})?(?-i)['\"][0-9a-zA-Z]{35,40}['\"]'''
	tags = ["key", "Github"]

[[rules]]
	description = "LinkedIn Client ID"
	regex = '''(?i)linkedin(.{0,20})?(?-i)['\"][0-9a-z]{12}['\"]'''
	tags = ["client", "LinkedIn"]

[[rules]]
	description = "LinkedIn Secret Key"
	regex = '''(?i)linkedin(.{0,20})?['\"][0-9a-z]{16}['\"]'''
	tags = ["secret", "LinkedIn"]

[[rules]]
	description = "Slack"
	regex = '''xox[baprs]-([0-9a-zA-Z]{10,48})?'''
	tags = ["key", "Slack"]

[[rules]]
	description = "EC"
	regex = '''-----BEGIN EC PRIVATE KEY-----'''
	tags = ["key", "EC"]

[[rules]]
	description = "Generic API key"
	regex = '''(?i)(api_key|apikey)(.{0,20})?['|"][0-9a-zA-Z]{32,45}['|"]'''
	tags = ["key", "API", "generic"]

[[rules]]
	description = "Generic Secret"
	regex = '''(?i)secret(.{0,20})?['|"][0-9a-zA-Z]{32,45}['|"]'''
	tags = ["key", "Secret", "generic"]

[[rules]]
	description = "Google API key"
	regex = '''AIza[0-9A-Za-z\\-_]{35}'''
	tags = ["key", "Google"]


[[rules]]
	description = "Heroku API key"
	regex = '''(?i)heroku(.{0,20})?['"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}['"]'''
	tags = ["key", "Heroku"]

[[rules]]
	description = "MailChimp API key"
	regex = '''(?i)(mailchimp|mc)(.{0,20})?['"][0-9a-f]{32}-us[0-9]{1,2}['"]'''
	tags = ["key", "Mailchimp"]

[[rules]]
	description = "Mailgun API key"
	regex = '''(?i)(mailgun|mg)(.{0,20})?['"][0-9a-z]{32}['"]'''
	tags = ["key", "Mailgun"]

[[rules]]
	description = "PayPal Braintree access token"
	regex = '''access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}'''
	tags = ["key", "Paypal"]

[[rules]]
	description = "Picatic API key"
	regex = '''sk_live_[0-9a-z]{32}'''
	tags = ["key", "Picatic"]

[[rules]]
	description = "Slack Webhook"
	regex = '''https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}'''
	tags = ["key", "slack"]

[[rules]]
	description = "Stripe API key"
	regex = '''(?i)stripe(.{0,20})?['\"][sk|rk]_live_[0-9a-zA-Z]{24}'''
	tags = ["key", "Stripe"]

[[rules]]
	description = "Square access token"
	regex = '''sq0atp-[0-9A-Za-z\-_]{22}'''
	tags = ["key", "square"]

[[rules]]
	description = "Square OAuth secret"
	regex = '''sq0csp-[0-9A-Za-z\\-_]{43}'''
	tags = ["key", "square"]

[[rules]]
	description = "Twilio API key"
	regex = '''(?i)twilio(.{0,20})?['\"][0-9a-f]{32}['\"]'''
	tags = ["key", "twilio"]

[[rules]]
	description = "AWS Manager ID"
	regex = '''(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}'''
	tags = ["key", "AWS"]

[whitelist]
	description = "image whitelists"
	file = '''(.*?)(jpg|gif|doc|pdf|bin)$'''
`

