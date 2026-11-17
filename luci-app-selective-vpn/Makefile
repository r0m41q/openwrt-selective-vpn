include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-selective-vpn
PKG_VERSION:=0.1.0
PKG_RELEASE:=5
PKG_LICENSE:=MIT

include $(INCLUDE_DIR)/package.mk

define Package/luci-app-selective-vpn
  SECTION:=luci
  CATEGORY:=LuCI
  SUBMENU:=3. Applications
  TITLE:=LuCI interface for Selective VPN
  URL:=https://github.com/r0m41q/openwrt-selective-vpn
  PKGARCH:=all
  DEPENDS:=+selective-vpn +luci-base +rpcd-mod-ucode +ucode-mod-fs +ucode-mod-uloop
endef

define Build/Configure
endef

define Build/Compile
endef

define Package/luci-app-selective-vpn/install
	$(INSTALL_DIR) $(1)/www/luci-static/resources/selective-vpn $(1)/www/luci-static/resources/view/selective-vpn
	$(INSTALL_DATA) ./htdocs/luci-static/resources/selective-vpn/*.js $(1)/www/luci-static/resources/selective-vpn/
	$(INSTALL_DATA) ./htdocs/luci-static/resources/view/selective-vpn/*.js $(1)/www/luci-static/resources/view/selective-vpn/
	$(INSTALL_DIR) $(1)/usr/share/rpcd/ucode $(1)/usr/share/rpcd/acl.d $(1)/usr/share/luci/menu.d
	$(INSTALL_DATA) ./root/usr/share/rpcd/ucode/selective-vpn $(1)/usr/share/rpcd/ucode/
	$(INSTALL_DATA) ./root/usr/share/rpcd/acl.d/luci-app-selective-vpn.json $(1)/usr/share/rpcd/acl.d/
	$(INSTALL_DATA) ./root/usr/share/luci/menu.d/luci-app-selective-vpn.json $(1)/usr/share/luci/menu.d/
	$(INSTALL_DIR) $(1)/usr/share/licenses/luci-app-selective-vpn
	$(INSTALL_DATA) ./LICENSE $(1)/usr/share/licenses/luci-app-selective-vpn/LICENSE
endef

$(eval $(call BuildPackage,luci-app-selective-vpn))
