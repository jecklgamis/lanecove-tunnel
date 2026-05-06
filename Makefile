DOCKER_IMAGE:=lanecove-tunnel-peer:latest
DEB_VERSION?=1.0.0
DEB_ARCH?=amd64
DEB_PKG:=lanecove-tunnel_$(DEB_VERSION)_$(DEB_ARCH)
DEB_ROOT:=build/$(DEB_PKG)
RPM_VERSION?=1.0.0
RPM_RELEASE?=1

RCUNIT_SRC := rcunit/src/rcunit.c rcunit/src/rcunit_assert.c rcunit/src/rcunit_error.c \
              rcunit/src/rcunit_exception.c rcunit/src/rcunit_function.c \
              rcunit/src/rcunit_hashtable.c rcunit/src/rcunit_list.c \
              rcunit/src/rcunit_machine.c rcunit/src/rcunit_mem.c \
              rcunit/src/rcunit_module.c rcunit/src/rcunit_mtrace.c \
              rcunit/src/rcunit_queue.c rcunit/src/rcunit_random.c \
              rcunit/src/rcunit_registry.c rcunit/src/rcunit_report.c \
              rcunit/src/rcunit_report_html.c rcunit/src/rcunit_report_json.c \
              rcunit/src/rcunit_report_plaintext.c rcunit/src/rcunit_report_xml.c \
              rcunit/src/rcunit_thread.c rcunit/src/rcunit_util.c

all:
	gcc -o lanecove src/peer.c src/common.c -lssl -lcrypto -lyaml
	chmod +x lanecove
image:
	docker build -t $(DOCKER_IMAGE) .
run-shell:
	@docker run -it --entrypoint /bin/bash $(DOCKER_IMAGE)
run:
	@docker run --rm 	--name lanecove-tunnel-peer -it $(DOCKER_IMAGE)
rpm: all
	mkdir -p build/rpm/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
	rpmbuild -bb \
		--define "_topdir $(CURDIR)/build/rpm" \
		--define "_sourcedir $(CURDIR)" \
		--define "pkg_version $(RPM_VERSION)" \
		--define "pkg_release $(RPM_RELEASE)" \
		rpm/lanecove-tunnel.spec
	@echo "Package built: $$(find build/rpm/RPMS -name '*.rpm')"
deb: all
	rm -rf $(DEB_ROOT)
	mkdir -p $(DEB_ROOT)/DEBIAN
	mkdir -p $(DEB_ROOT)/usr/bin
	mkdir -p $(DEB_ROOT)/usr/share/lanecove-tunnel
	mkdir -p $(DEB_ROOT)/lib/systemd/system
	mkdir -p $(DEB_ROOT)/etc/lanecove
	install -m 755 lanecove $(DEB_ROOT)/usr/bin/lanecove-peer
	install -m 755 scripts/lanecove-create-tunnel.sh $(DEB_ROOT)/usr/share/lanecove-tunnel/
	install -m 755 scripts/lanecove-extract-keys-hex.sh $(DEB_ROOT)/usr/bin/
	install -m 755 scripts/lanecove-extract-pubkey-hex.sh $(DEB_ROOT)/usr/bin/
	install -m 755 scripts/lanecove-generate-peer-keys.sh $(DEB_ROOT)/usr/bin/
	install -m 755 scripts/lanecove-create-tunnel.sh $(DEB_ROOT)/usr/bin/
	install -m 644 debian/systemd/lanecove-relay.service $(DEB_ROOT)/lib/systemd/system/
	install -m 644 debian/systemd/lanecove-peer.service $(DEB_ROOT)/lib/systemd/system/
	install -m 644 debian/systemd/lanecove-peer-1.service $(DEB_ROOT)/lib/systemd/system/
	install -m 644 debian/systemd/lanecove-peer-2.service $(DEB_ROOT)/lib/systemd/system/
	install -m 640 config/relay.yaml $(DEB_ROOT)/etc/lanecove/relay.yaml
	install -m 640 config/peer.yaml $(DEB_ROOT)/etc/lanecove/peer.yaml
	install -m 640 config/peer-1.yaml $(DEB_ROOT)/etc/lanecove/peer-1.yaml
	install -m 640 config/peer-2.yaml $(DEB_ROOT)/etc/lanecove/peer-2.yaml
	sed -e "s/^Architecture:.*/Architecture: $(DEB_ARCH)/" -e "s/^Version:.*/Version: $(DEB_VERSION)/" debian/control > $(DEB_ROOT)/DEBIAN/control
	install -m 755 debian/postinst $(DEB_ROOT)/DEBIAN/postinst
	install -m 755 debian/prerm $(DEB_ROOT)/DEBIAN/prerm
	dpkg-deb --build $(DEB_ROOT) build/$(DEB_PKG).deb
	@echo "Package built: build/$(DEB_PKG).deb"
test:
	mkdir -p build
	gcc -o build/run_tests tests/test_common.c src/common.c $(RCUNIT_SRC) \
		-I rcunit/src -lssl -lcrypto -lyaml -lpthread -lm
	./build/run_tests
test-using-docker:
	mkdir -p build
	docker run --rm -v $(CURDIR):/lanecove -w /lanecove debian:bookworm-slim bash -c \
		"apt-get update -q && apt-get install -y -q gcc make libssl-dev libyaml-dev && \
		gcc -o build/run_tests tests/test_common.c src/common.c $(RCUNIT_SRC) \
		-I rcunit/src -lssl -lcrypto -lyaml -lpthread -lm && \
		./build/run_tests"
clean:
	rm -f ./lanecove
	rm -rf build/
