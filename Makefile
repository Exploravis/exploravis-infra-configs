.PHONY: bootstrap

bootstrap:
	bash ./scripts/bootstrap-direct.sh
k3d-cluster: 
	k3d cluster create exploravis-dev --servers 1 --agents 2 --k3s-arg "--disable=traefik@server:*"
