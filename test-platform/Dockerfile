# Deliberately NON-COMPLIANT Ubuntu target for the test platform.
# Every rule in benchmarks/linux_baseline.yml should FAIL on this image
# before remediation and PASS after the generated Chef cookbook runs.
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# openssh-server provides sshd_config; telnet is the "forbidden" package;
# Cinc Client is the community build of Chef Infra Client (no license key needed).
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server telnet curl ca-certificates \
 && curl -fsSL https://omnitruck.cinc.sh/install.sh | bash -s -- -v 18

# Insecure configuration on purpose.
COPY insecure_sshd_config /etc/ssh/sshd_config
RUN chmod 0644 /etc/shadow \
 && sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t99999/' /etc/login.defs

CMD ["sleep", "infinity"]
