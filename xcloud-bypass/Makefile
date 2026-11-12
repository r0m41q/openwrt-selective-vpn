include $(TOPDIR)/rules.mk

PKG_NAME:=xcloud-bypass
PKG_VERSION:=0.1.0
PKG_RELEASE:=1
PKG_LICENSE:=MIT

include $(INCLUDE_DIR)/package.mk

define Package/xcloud-bypass
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Routing and Redirection
  TITLE:=Selective Xbox Cloud Gaming authentication routing
  URL:=https://github.com/r0m41q/openwrt-xcloud-bypass
  PKGARCH:=all
  DEPENDS:=+pbr +openvpn-openssl +firewall4 +uci +ubus +jshn +jsonfilter +ip-full +nftables-json
endef

define Package/xcloud-bypass/description
  Route selected Xbox Cloud Gaming authentication connections through OpenVPN.
  Configuration is disabled by default and kept separate from existing policies.
endef

define Package/xcloud-bypass/conffiles
/etc/config/xcloud-bypass
endef

define Build/Configure
endef

define Build/Compile
endef

define Package/xcloud-bypass/install
	$(INSTALL_DIR) $(1)/etc/config $(1)/usr/lib/xcloud-bypass
	$(INSTALL_CONF) ./files/etc/config/xcloud-bypass $(1)/etc/config/xcloud-bypass
	$(INSTALL_DATA) ./files/usr/lib/xcloud-bypass/*.sh $(1)/usr/lib/xcloud-bypass/
	$(INSTALL_DATA) ./files/usr/lib/xcloud-bypass/*.awk $(1)/usr/lib/xcloud-bypass/
endef

$(eval $(call BuildPackage,xcloud-bypass))
