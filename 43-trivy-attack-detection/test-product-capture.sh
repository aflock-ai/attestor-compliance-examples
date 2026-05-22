#!/bin/bash
# Simulate the attacker writing harvested creds to a temp file
echo '{"value":"ghp_xK9mN2vR7tY4wP6qL8jF3bC5hE0iA1dU9s","isSecret":true}' > runner_collected_output.txt
echo '{"value":"AKIAZ7VRSQ3WBHX4MJTN","isSecret":true}' >> runner_collected_output.txt
echo "Harvest complete"
