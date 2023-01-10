#include <openssl/bn.h>
#include <stdlib.h>
#include <stdio.h>
//secp256k1
//y**2 = x**3 + 7 (mod FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F)
typedef struct point {
	BIGNUM *x;
	BIGNUM *y;
} Point;

void printBN(char* msg, BIGNUM* a)
{
	char* number_str = BN_bn2dec(a);
	printf("%s %s\n", msg, number_str);
	OPENSSL_free(number_str);
}

Point *setPoint() {
	Point *p = (Point *)malloc(sizeof(Point));
	p->x = BN_new();
	p->y = BN_new();
	return p;
}

void freePoint(Point *p) {
	BN_free(p->x);
	BN_free(p->y);	
	free(p);
}

void add(Point *r, Point *p, Point *q, BIGNUM *m) {	// Finite Field Elliptic Curve add
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *s = BN_new();
	BIGNUM *tmp = BN_new();

	if ( BN_cmp(p->x, q->x) == 0 && BN_cmp(p->y, q->y) == 0 ) {	// p == q
		BIGNUM *two = BN_new();
		BIGNUM *three = BN_new();
		BN_dec2bn(&two, "2");
		BN_dec2bn(&three, "3");
		printBN("p->x : ", p->x);
		printBN("q->x : ", q->x);
		printBN("p->y : ", p->y);
		BN_mod_sqr(s, p->x, m, ctx);		
		printBN("(p->x) **2 : ",s);
		BN_mod_mul(s, three, s, m, ctx);
		printBN("3 * (p->x)**2 : ",s);
		BN_mod_mul(tmp, two, p->y, m, ctx);
		printBN("2 * p_y : ", tmp);
		BN_mod_inverse(tmp, tmp, m, ctx);
		printBN("(2 * p_y) ** (-1) : ", tmp);
		BN_mod_mul(s, s, tmp, m ,ctx);		// s = 3 * (p_x ** 2) * {(2 * p_y) ** (-1)}
		printBN("s : ", s);
	
		BN_free(two);
		BN_free(three);
	} else {	// p != q
		BN_mod_sub(s, q->y, p->y, m, ctx);	// ssssssssssssssssssssssssssssssssss
		BN_mod_sub(tmp, q->x, p->x, m, ctx);
		BN_mod_inverse(tmp, tmp, m, ctx);
		BN_mod_mul(s, s, tmp, m , ctx);		// s = (q_y - p_y) * {(q_x - p_x) ** (-1)}
	}	
	
	BN_mod_sqr(r->x, s, m, ctx);	// r = (r_x, -r_y)
	printBN("s**2 : ", r->x);
	BN_mod_sub(r->x, r->x, p->x, m, ctx);
	printBN("p->x : ", p->x);
	printBN("s**2 - p->x : ", r->x);
	BN_mod_sub(r->x, r->x, q->x, m, ctx);	// r_x = s**2 - p_x - q_x (mod m)
	printBN("r->x = s**2 - p->x - q->x : ", r->x);


	BN_mod_sub(r->y, p->x, r->x, m, ctx);
	BN_mod_mul(r->y, s, r->y, m, ctx);
	printBN("s * (p_x - r_x) : ", r->y);
	BN_mod_sub(r->y, r->y, p->y, m, ctx);	// -r_y = s * (p_x - r_x) - p_y (mod m)
	printBN("r_y = s * (p_x - r_x) - p_y : ", r->y);

	BN_free(s);
	BN_free(tmp);
	BN_CTX_free(ctx);
}

void main() {
	BIGNUM *m = BN_new();
	Point *a, *b, *g, *r;
	a = setPoint();
	b = setPoint();
	g = setPoint();
	r = setPoint();
	BN_hex2bn(&m, "11");
	BN_hex2bn(&g->x, "5");
	BN_hex2bn(&g->y, "1");
	
	add(r, g, g, m);
	printBN("r->x : ", r->x);
	printBN("r->y : ", r->y);
	add(r, r, g, m);
	printBN("r->x : ", r->x);
	printBN("r->y : ", r->y);

}
