include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-xcloud-bypass
PKG_VERSION:=0.1.0
PKG_RELEASE:=1
PKG_LICENSE:=MIT

include $(INCLUDE_DIR)/package.mk

define Package/luci-app-xcloud-bypass
  SECTION:=luci
  CATEGORY:=LuCI
  SUBMENU:=3. Applications
  TITLE:=LuCI interface for XCloud Gaming bypass
  URL:=https://github.com/r0m41q/openwrt-xcloud-bypass
  PKGARCH:=all
  DEPENDS:=+xcloud-bypass +luci-base +rpcd-mod-ucode +ucode-mod-fs +ucode-mod-uloop
endef

define Build/Configure
endef

define Build/Compile
endef

define Package/luci-app-xcloud-bypass/install
	$(INSTALL_DIR) $(1)/www/luci-static/resources/xcloud-bypass $(1)/www/luci-static/resources/view/xcloud-bypass
	$(INSTALL_DATA) ./htdocs/luci-static/resources/xcloud-bypass/*.js $(1)/www/luci-static/resources/xcloud-bypass/
	$(INSTALL_DATA) ./htdocs/luci-static/resources/view/xcloud-bypass/*.js $(1)/www/luci-static/resources/view/xcloud-bypass/
	$(INSTALL_DIR) $(1)/usr/share/rpcd/ucode $(1)/usr/share/rpcd/acl.d $(1)/usr/share/luci/menu.d
	$(INSTALL_DATA) ./root/usr/share/rpcd/ucode/xcloud-bypass $(1)/usr/share/rpcd/ucode/
	$(INSTALL_DATA) ./root/usr/share/rpcd/acl.d/luci-app-xcloud-bypass.json $(1)/usr/share/rpcd/acl.d/
	$(INSTALL_DATA) ./root/usr/share/luci/menu.d/luci-app-xcloud-bypass.json $(1)/usr/share/luci/menu.d/
	$(INSTALL_DIR) $(1)/usr/share/licenses/luci-app-xcloud-bypass
	$(INSTALL_DATA) ./LICENSE $(1)/usr/share/licenses/luci-app-xcloud-bypass/LICENSE
endef

$(eval $(call BuildPackage,luci-app-xcloud-bypass))
