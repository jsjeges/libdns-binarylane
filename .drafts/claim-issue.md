I'd like to claim Binary Lane (https://www.binarylane.com.au), an Australian
cloud provider whose DNS is managed through the Domains endpoints of its
public API.

It's a straightforward REST API — its OpenAPI description is published at
https://api.binarylane.com.au/reference/openapi.json — and I use it for my
own zones, so I'm happy to maintain the package.

I have an implementation working against libdns v1.1.1 and will open a PR for
review once I've run it against a live zone.
