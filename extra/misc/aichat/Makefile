COMMENT =	all-in-one LLM CLI tool with shell assistant, REPL, RAG, and agents

V =		0.30.0
DISTNAME =	aichat-${V}
GH_ACCOUNT =	sigoden
GH_PROJECT =	aichat
GH_TAGNAME =	v${V}

CATEGORIES =	misc devel

HOMEPAGE =	https://github.com/sigoden/aichat

# MIT OR Apache-2.0
PERMIT_PACKAGE =	Yes

WANTLIB =	c m pthread

MODULES =	devel/cargo

CONFIGURE_STYLE =	cargo

post-install:
	${INSTALL_DATA_DIR} ${PREFIX}/share/bash-completion/completions
	${INSTALL_DATA} ${WRKSRC}/scripts/completions/aichat.bash \
		${PREFIX}/share/bash-completion/completions/aichat
	${INSTALL_DATA_DIR} ${PREFIX}/share/fish/vendor_completions.d
	${INSTALL_DATA} ${WRKSRC}/scripts/completions/aichat.fish \
		${PREFIX}/share/fish/vendor_completions.d/aichat.fish
	${INSTALL_DATA_DIR} ${PREFIX}/share/zsh/site-functions
	${INSTALL_DATA} ${WRKSRC}/scripts/completions/aichat.zsh \
		${PREFIX}/share/zsh/site-functions/_aichat

.include "crates.inc"

.include <bsd.port.mk>
