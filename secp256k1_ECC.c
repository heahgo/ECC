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
	
	BN_mod_sqr(tmp, s, m, ctx);	// r = (r_x, -r_y)
	printBN("p->x : ", p->x);
	printBN("s**2 : ", s);
	printBN("p->x : ", p->x);
	BN_mod_sub(r->x, tmp, p->x, m, ctx);
	printBN("s**2 - p->x : ", r->x);	// why r_x = 0 ???
	BN_mod_sub(r->x, r->x, q->x, m, ctx);	// r_x = s**2 - p_x - q_x (mod m)
    printBN("r->x = s**2 - p->x - q->x : ", r->x);


	BN_mod_sub(tmp, p->x, r->x, m, ctx);
	printBN("p->x - r->x : ", tmp);
	BN_mod_mul(r->y, s, tmp, m, ctx);
	printBN("s * (p_x - r_x) : ", r->y);
	printBN("q->y : ", q->y);
	BN_mod_sub(r->y, r->y, p->y, m, ctx);	// -r_y = s * (p_x - r_x) - p_y (mod m)
	printBN("r_y = s * (p_x - r_x) - p_y : ", r->y);
	printf("---------------------------------------------------------------------------------------------------------------------------\n");
	BN_free(s);
	BN_free(tmp);
	BN_CTX_free(ctx);
}

void mul(Point *r, Point *p, int n, BIGNUM *m) {
	BN_copy(r->x, p->x);
	BN_copy(r->y, p->y);

	for (int i = 0; i < n - 1; i++ ) {
		printf("\n");
		printf("\n");
		add(r, r, p, m);
	}
}

void main() {
	BIGNUM *m = BN_new();
	Point *a, *b, *g, *r;
	a = setPoint();
	b = setPoint();
	g = setPoint();
	r = setPoint();
	BN_hex2bn(&m, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
	BN_hex2bn(&g->x, "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");
	BN_hex2bn(&g->y, "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");

	mul(a, g, 3, m);
	printBN("a->x : ", a->x);
	printBN("a->y : ", a->y);
	printBN("b->x : ", b->x);
	printBN("b->y : ", b->y);
	printf("\n");
	printf("------------------------------\n");
	mul(b, g, 7, m);
	printBN("a->x : ", a->x);
	printBN("a->y : ", a->y);
	printBN("b->x : ", b->x);
	printBN("b->y : ", b->y);
	printf("\n");
	printf("------------------------------\n");
	mul(a, a, 7, m);
	printf("------------------------------\n");
	mul(b, b, 3, m);
	printBN("a->x : ", a->x);
	printBN("a->y : ", a->y);
	printBN("b->x : ", b->x);
	printBN("b->y : ", b->y);

	BN_free(m);
	freePoint(a);
	freePoint(b);
	freePoint(r);
	freePoint(g);
}
