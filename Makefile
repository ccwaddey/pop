all: popd authpop wrkrpop

popd: pop.c imsgpop.h logutil.h logutil.c
	cc -ggdb -Wall -o popd pop.c logutil.c -lutil -levent

authpop: authpop.c imsgpop.h logutil.h logutil.c
	cc -ggdb -Wall -o authpop authpop.c logutil.c -lutil -levent -ltls

wrkrpop: wrkrpop.c imsgpop.h logutil.h logutil.c
	cc -ggdb -Wall -o wrkrpop wrkrpop.c logutil.c -lutil -levent -lcrypto

tags:
	etags wrkrpop.c authpop.c pop.c imsgpop.h logutil.h logutil.c

wc:
	wc *.[ch]
