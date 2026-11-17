include $(TOPDIR)/rules.mk

PKG_NAME:=selective-vpn
PKG_VERSION:=0.1.0
PKG_RELEASE:=7
PKG_LICENSE:=MIT

include $(INCLUDE_DIR)/package.mk

define Package/selective-vpn
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Routing and Redirection
  TITLE:=Selective VPN routing
  URL:=https://github.com/r0m41q/openwrt-selective-vpn
  PKGARCH:=all
  DEPENDS:=+pbr +openvpn-openssl +firewall4 +uci +ubus +jshn +jsonfilter +ip-full +nftables-json +flock +ss +coreutils-stat +coreutils-timeout
endef

define Package/selective-vpn/description
  Route selected destinations through an OpenVPN connection.
  Configuration is disabled by default and kept separate from existing policies.
endef

define Package/selective-vpn/conffiles
/etc/config/selective-vpn
endef

define Package/selective-vpn/prerm
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] && exit 0
if [ -e /etc/selective-vpn/pending ] || \
   { [ "$${PKG_UPGRADE}" != 1 ] && uci -q show selective-vpn.svpn_active >/dev/null 2>&1; }; then
	[ "$${PKG_UPGRADE}" = 1 ] || /etc/init.d/selective-vpn enable
	/etc/init.d/selective-vpn start
	echo 'Finish or roll back pending changes, then run selective-vpn uninstall before removing the package.' >&2
	exit 1
fi
endef

define Build/Configure
endef

define Build/Compile
endef

define Package/selective-vpn/install
	$(INSTALL_DIR) $(1)/etc/config $(1)/usr/lib/selective-vpn $(1)/usr/bin
	$(INSTALL_CONF) ./files/etc/config/selective-vpn $(1)/etc/config/selective-vpn
	$(INSTALL_DATA) ./files/usr/lib/selective-vpn/*.sh $(1)/usr/lib/selective-vpn/
	$(INSTALL_DATA) ./files/usr/lib/selective-vpn/*.awk $(1)/usr/lib/selective-vpn/
	$(INSTALL_DATA) ./files/usr/lib/selective-vpn/presets $(1)/usr/lib/selective-vpn/
	$(INSTALL_BIN) ./files/usr/lib/selective-vpn/recovery-watch $(1)/usr/lib/selective-vpn/
	$(INSTALL_BIN) ./files/usr/lib/selective-vpn/control $(1)/usr/lib/selective-vpn/
	$(INSTALL_BIN) ./files/usr/lib/selective-vpn/rpc-bridge $(1)/usr/lib/selective-vpn/
	$(INSTALL_BIN) ./files/usr/bin/selective-vpn $(1)/usr/bin/
	$(INSTALL_BIN) ./files/usr/lib/selective-vpn/supervise $(1)/usr/lib/selective-vpn/
	$(INSTALL_BIN) ./files/usr/lib/selective-vpn/signal-event $(1)/usr/lib/selective-vpn/
	$(INSTALL_BIN) ./files/usr/lib/selective-vpn/service-run $(1)/usr/lib/selective-vpn/
	$(INSTALL_DIR) $(1)/etc/init.d $(1)/etc/hotplug.d/iface $(1)/etc/hotplug.d/openvpn
	$(INSTALL_BIN) ./files/etc/init.d/selective-vpn $(1)/etc/init.d/selective-vpn
	$(INSTALL_DATA) ./files/etc/hotplug.d/iface/95-selective-vpn $(1)/etc/hotplug.d/iface/
	$(INSTALL_DATA) ./files/etc/hotplug.d/openvpn/95-selective-vpn $(1)/etc/hotplug.d/openvpn/
	$(INSTALL_DIR) $(1)/usr/share/licenses/selective-vpn
	$(INSTALL_DATA) ./LICENSE $(1)/usr/share/licenses/selective-vpn/LICENSE
endef

$(eval $(call BuildPackage,selective-vpn))
