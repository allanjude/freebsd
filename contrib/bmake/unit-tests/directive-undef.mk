# $NetBSD: directive-undef.mk,v 1.4 2020/10/24 08:46:08 rillig Exp $
#
# Tests for the .undef directive.

# As of 2020-07-28, .undef only undefines the first variable.
# All further variable names are silently ignored.
# See parse.c, string literal "undef".
1=		1
2=		2
3=		3
.undef 1 2 3
.if ${1:U_}${2:U_}${3:U_} != _23
.  warning $1$2$3
.endif

all:
	@:;
