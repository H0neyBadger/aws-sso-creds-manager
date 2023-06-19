Generate "legacy" `~/.aws/credentials` from aws sso config.

`~/.aws/config` example:
```ini
[profile default]
sso_session = default
sso_account_id = 1234567890
sso_role_name = 1234567890.read
region = us-east-1

[profile write]
sso_session = default
sso_account_id = 1234567890
sso_role_name = 1234567890.write
region = us-east-1

[sso-session default]
sso_start_url = https://x-abcdef0123.awsapps.com/start
sso_region = us-east-1
sso_registration_scopes = sso:account:access
```

```bash
AWS_DEFAULT_REGION=us-east-1 aws-sso-creds-manager 
```