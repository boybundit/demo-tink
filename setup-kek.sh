curl --request POST --header "X-Vault-Token: root" \
  --data '{"type":"transit"}' --insecure \
  https://localhost:8200/v1/sys/mounts/transit

curl --request POST --header "X-Vault-Token: root" \
  --data '{"type":"aes128-gcm96"}' --insecure \
  https://localhost:8200/v1/transit/keys/demo-tink
