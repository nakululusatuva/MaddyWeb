# Add exactly this managed include inside the existing
# /etc/custom-acme/nginx.conf "http" block.
include /etc/custom-acme/maddyweb/cloudflare-http.conf;
include /etc/custom-acme/maddyweb/maddy.custom.example.test.conf;
