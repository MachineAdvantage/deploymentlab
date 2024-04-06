# Machine Advantage Development Lab
This repo represents the entry point for all of the different things we are just testing out and want to be web-facing.

A simple cloud hosted LLM-powered unit test creator that ensures that the code can actually run in the context of code.

Be sure that you add the passwords for your db to a file called `.env` at the same level as the docker-compose. DO NOT PUSH YOUR PASSWORDS TO GIT.

## Setup

When developing don't forget to run ngrok to forward your local server to an HTTPS endpoint, because without HTTPS Auth will not work.

### Acknowledgement

A huge thanks to @rickh94 for his tutorial on, basically, exactly this approach to authentication in production-quality containerized flask apps, and @xxbidiao for all of his helpful advice and prior experience on locally hosted LLMs.
