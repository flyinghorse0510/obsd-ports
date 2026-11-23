COMMENT =	extensible open-source AI agent

V =		1.60.2
GH_ACCOUNT =	block
GH_PROJECT =	goose
GH_TAGNAME =	v${V}

DIST_TUPLE +=	github jbg cudaforge e7c1967340e40673db98dc9e17da0f04834a456f modcargo-crates/cudaforge-0.1.6

CATEGORIES =	devel

HOMEPAGE =	https://block.github.io/goose/

# Apache-2.0
PERMIT_PACKAGE =	Yes

WANTLIB =	c m pthread

MODULES =	devel/cargo

CONFIGURE_STYLE =		cargo
MODCARGO_INSTALL_TARGET_PATHS =	crates/goose-cli
MODCARGO_NO_DEFAULT_FEATURES =	Yes
MODCARGO_FEATURES =		portable-default code-mode online-model-meta disable-update

.include "crates.inc"

.include <bsd.port.mk>
