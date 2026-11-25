include $(BASE)/Makefile.inc

S = etc_init.d_tac_plus
E = $(INSTALLROOT)$(LIBARCHDIR_DEST)/mavis/extra

all: $(S)

$(S): ../../spawnd/extra/etc_init.d_spawnd
	sed -e 's/spawnd/tac_plus/g' -e 's/^\(# Short-Description:\) .*/\1 TACACS+ daemon/'< $^ > $@

$(E)/$(S): $(S) | $(E)
	$(INSTALL) -m 0755 $^ $@

$(E):
	@mkdir -p -m 0755 $@

$(INSTALLROOT)$(SBINDIR_DEST):
	@mkdir -p -m 0755 $@

$(E)/de.pro-bono-publico.tac_plus.plist: de.pro-bono-publico.tac_plus.plist | $(E)
	$(INSTALL) -m 0644 $^ $@

$(E)/tac_plus.cfg-ads: tac_plus.cfg-ads | $(E)
	$(INSTALL) -m 0644 $^ $@

$(E)/tac_plus.service: tac_plus.service | $(E)
	$(INSTALL) -m 0644 $^ $@

$(INSTALLROOT)$(SBINDIR_DEST)/tacspooflog.pl: tacspooflog.pl | $(INSTALLROOT)$(SBINDIR_DEST)
	$(INSTALL) -m 0755 $^ $@

install: $(E) $(E)/$(S) $(E)/de.pro-bono-publico.tac_plus.plist $(E)/etc_init.d_tac_plus $(E)/tac_plus.cfg-ads $(E)/tac_plus.service $(INSTALLROOT)$(SBINDIR_DEST)/tacspooflog.pl

