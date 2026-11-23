COMMENT =	AI-enabled pair programmer and coding agent for the terminal

V =		2.14.0
DISTNAME =	forge-${V}
PKGNAME =	forgecode-${V}

GH_ACCOUNT =	antinomyhq
GH_PROJECT =	forge
GH_TAGNAME =	v${V}

CATEGORIES =	devel

HOMEPAGE =	https://forgecode.dev/

# Apache-2.0
PERMIT_PACKAGE =	Yes

WANTLIB =	c m pthread

MODULES =	devel/cargo

CONFIGURE_STYLE =	cargo

.include "crates.inc"

.include <bsd.port.mk>
