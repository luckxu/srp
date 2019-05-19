PWD = $(shell pwd)/../..
DOCKER_IMAGE=srp-$(TGT)-dev

all:
	@docker run --rm -v $(PWD):/opt $(DOCKER_IMAGE) make -C /opt/ release
	@rm -rf tmp
	@mkdir tmp
	@cp $(PWD)/srps tmp/
	@cp ../srps.conf tmp/
	@cp dockerfile tmp/Dockerfile
	@docker build -t luckxu/srps:$(VERSION)-$(TGT) tmp
	@cp $(PWD)/srpn tmp/
	@cp ../srpn.conf tmp/
	@sed -i '/EXPOSE/d' tmp/Dockerfile
	@sed -i 's/srps/srpn/g' tmp/Dockerfile
	@docker build -t luckxu/srpn:$(VERSION)-$(TGT) tmp
	@rm -rf tmp

