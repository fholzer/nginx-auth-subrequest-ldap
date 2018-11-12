PKGNAME=nginx-auth-subrequest-ldap
PKGVERSION=1.1
PKGRELEASE=2

GO_PROJECT_FILES=$(shell find -maxdepth 1 -type f -name '*.go')
GO_VENDOR_FILES=$(shell find vendor/ -type f -name '*.go')
GO_FILES=$(GO_PROJECT_FILES) $(GO_VENDOR_FILES)
EXAMPLE_FILES=$(shell find examples/ -type f)

nginx-auth-subrequest-ldap: $(GO_FILES)
	go build -ldflags "-s -w"

.PHONY: setup
setup:
	go get github.com/fzipp/gocyclo
	go get -u golang.org/x/lint/golint
	go get github.com/gordonklaus/ineffassign
	go get -u github.com/client9/misspell/cmd/misspell
	dep ensure

.PHONY: prepare
prepare:
	go fmt -x .
	go vet .
	gocyclo -over 15 main.go
	golint
	ineffassign .
	misspell -error main

rpmbuild/SOURCES/$(PKGNAME)-v$(PKGVERSION).tar.gz: $(GO_FILES) $(EXAMPLE_FILES)
	tar --exclude="./rpmbuild" --transform 's,^\.,./nginx-auth-subrequest-ldap,' -czf rpmbuild/SOURCES/$(PKGNAME)-v$(PKGVERSION).tar.gz .

rpmbuild/SPECS/$(PKGNAME).spec: $(PKGNAME).spec
	cp $(PKGNAME).spec rpmbuild/SPECS

.PHONY: rpm-init
rpm-init:
	for i in SOURCES SPECS SRPMS RPMS BUILD BUILDROOT; do \
		mkdir -p rpmbuild/$$i; \
	done

.PHONY: rpm-prepare
rpm-prepare: rpm-init rpmbuild/SPECS/$(PKGNAME).spec rpmbuild/SOURCES/$(PKGNAME)-v$(PKGVERSION).tar.gz

.PHONY: package
package: rpm-prepare
	rpmbuild -bb \
	-D "_topdir $(PWD)/rpmbuild" \
	-D "PKGVERSION $(PKGVERSION)" \
	-D "PKGRELEASE $(PKGRELEASE)" \
	-D "packager $(USER)@gvcgroup.com" \
	$(PKGNAME).spec

.PHONY: release
release: clean bumpRelease
	make build

.PHONY: bumpdRelease
bumpRelease:
	mv Makefile Makefile.bak
	awk '/^PKGRELEASE=[1-9][0-9]*/{n = substr($$0, match($$0, /[0-9]+/), RLENGTH) + 1; sub(/[0-9]+/, n); print; next} {print}' Makefile.bak >Makefile

.PHONY: clean
clean:
	$(RM) -r rpmbuild
