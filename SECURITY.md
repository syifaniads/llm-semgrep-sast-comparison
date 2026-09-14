# Security Policy

This repository contains intentionally vulnerable code fixtures for educational static-analysis testing.

## Do not use the vulnerable samples in production

Files under `vulnerable-samples/` intentionally demonstrate insecure patterns such as injection, unsafe deserialization and hardcoded-secret examples. They exist only as scanner fixtures.

## Secrets

Never add a real API key, cloud credential, JWT signing secret or password to the sample corpus. Use obviously fake placeholders.

Real model credentials must be supplied through environment variables and should never be committed.

## Generated results

`results/` is ignored by default. Generated reports may contain code excerpts and model output; review them before sharing publicly if scanning anything other than the included lab fixtures.