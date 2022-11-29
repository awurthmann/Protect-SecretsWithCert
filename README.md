# Protect-SecretsWithCert

## Legal
You the executor, runner, user accept all liability.
This code comes with ABSOLUTELY NO WARRANTY.
This is free and unencumbered software released into the public domain.
Anyone is free to copy, modify, publish, use, compile, sell, or
distribute this software, either in source code form or as a compiled
binary, for any purpose, commercial or non-commercial, and by any
means.

## About:
This script is a collection of functions that can be used to obfuscate passwords and secrets using a local certificate and Public/Private key pair. The use case here is that different users on the same local system need access to the secret(s) without storing them all individually. In highly secure environments I'd tactical this differently, perhaps separate the script runner out from job executor, and perhaps separating the systems. e.g. The user on one system submits a job or drops a text file on another system and that system processes the file using the locally stored secrets.

## Instructions:
See "Examples" section in Protect-SecretsWithCert.ps1
