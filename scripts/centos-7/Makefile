DIR=/root/rpmbuild
DATE=$(shell date +"%a %b %m %Y")

all: srpn-rpm srps-rpm

%-rpm:
	rpmdev-setuptree
	mkdir $(DIR)/SOURCES/$*-$(VERSION) -p
	cp /opt/* $(DIR)/SOURCES/$*-$(VERSION) -r
	cp $(DIR)/SOURCES/$*-$(VERSION)/scripts/centos-7/$*.specs $(DIR)/SPECS/
	cd $(DIR)/SOURCES && tar -cvzf $*-$(VERSION).tar.gz $*-$(VERSION)/
	sed -i "s/{VERSION}/$(VERSION)/g" $(DIR)/SPECS/$*.specs
	sed -i "s/{DATE}/$(DATE)/g" $(DIR)/SPECS/$*.specs
	rpmbuild -bb $(DIR)/SPECS/$*.specs
	mkdir -p /opt/output/centos-7
	find $(DIR)/RPMS/* -name "$*-*" | xargs -i cp {} /opt/output/centos-7