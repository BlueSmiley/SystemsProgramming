/* Copyright (c) 2013-2017 the Civetweb developers
 * Copyright (c) 2013 No Face Press, LLC
 * License http://opensource.org/licenses/mit-license.php MIT License
 */

// Simple example program on how to use Embedded C++ interface.
#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#endif

#include "CivetServer.h"
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

#include "mbedtls/bignum.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

#define DOCUMENT_ROOT "."
#define PORT "8081"
#define EXIT_URI "/.well-known/vpexit"
bool exitNow = false;

class ExitHandler : public CivetHandler
{
  public:
	bool
	handleGet(CivetServer *server, struct mg_connection *conn)
	{
		mg_printf(conn,
		          "HTTP/1.1 200 OK\r\nContent-Type: "
		          "text/plain\r\nConnection: close\r\n\r\n");
		mg_printf(conn, "Bye\n");
		exitNow = true;
		return true;
	}
};

uint8_t*
hex_decode(const char *in, size_t len,uint8_t *out,bool *ret)
{
        unsigned int i, t, hn, ln;
		//newly added code if length>max
		if(len>128)
		{
			*ret = false;
			return out;
		}
        for (t = 0,i = 0; i < len; i+=2,++t) {
			if(in[i]>'f' || in[i+1]>'f')
			{
				//if not hex
				*ret = false;
				return out;
			}
        	hn = in[i] > '9' ? (in[i]|32) - 'a' + 10 : in[i] - '0';
            ln = in[i+1] > '9' ? (in[i+1]|32) - 'a' + 10 : in[i+1] - '0';

            out[t] = (hn << 4 ) | ln;
        }
		*ret = true;
        return out;
}

class FooHandler : public CivetHandler
{
  public:
	bool
	handleGet(CivetServer *server, struct mg_connection *conn)
	{
		/* Handler may access the request info using mg_get_request_info */
		const struct mg_request_info *req_info = mg_get_request_info(conn);
		mg_printf(conn,
		          "HTTP/1.1 200 OK\r\nContent-Type: "
		"text/plain\r\nConnection: close\r\n\r\n");
		const char *vanity = (req_info->query_string) + 5;
		int len = strlen(vanity);
		//prime generation;
		//char to hex minimum half the size of current array
		uint8_t result[len/2];
		//hex decode converts char to unsigned 8 bit int
		bool ret = true;
		uint8_t *res = hex_decode(vanity,len,result,&ret);
		if(!ret)
		{
			mg_printf(conn,"Error 400: Bad Request");
			//ok i don't know what this boolean value is meant to mean'
			return true;
		}
		//number of bytes not bits actually
		int nbits = 128;
		mbedtls_mpi G;
		mbedtls_mpi_init( &G );
		mbedtls_entropy_context entropy;
    	mbedtls_ctr_drbg_context ctr_drbg;
    	const char *pers = "dh_genprime";
		mbedtls_ctr_drbg_init( &ctr_drbg );
    	mbedtls_entropy_init( &entropy );
		//seed randomness
		mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) );
		//generate random prime of sufficent bits					   
		mbedtls_mpi_gen_prime( &G, 1024, 1,
				mbedtls_ctr_drbg_random, &ctr_drbg);

		unsigned char prime[nbits];
		//write random prime into buffer of correct size
		mbedtls_mpi_write_binary(&G,prime,nbits);
		//superimpose hex array to start of prime array
		memcpy(prime,res,len/2);
		//reread the hex array back into struct for generating primes
		mbedtls_mpi_read_binary(&G,prime,nbits);
		while(mbedtls_mpi_is_prime( &G, mbedtls_ctr_drbg_random, &ctr_drbg )!=0)
			mbedtls_mpi_add_int(&G,&G,2);
		mbedtls_mpi_write_binary(&G,prime,nbits);
		//print the array out as hex numbers
		for(int i=0;i<nbits;i++)
			mg_printf(conn,
		          "%02x",
		          prime[i]);
		return true;
	}
};


int
process(int argc, char *argv[])
{
	const char *options[] = {
	    "document_root", DOCUMENT_ROOT, "listening_ports", PORT, 0};
    
    std::vector<std::string> cpp_options;
    for (int i=0; i<(sizeof(options)/sizeof(options[0])-1); i++) {
        cpp_options.push_back(options[i]);
    }

	// CivetServer server(options); // <-- C style start
	CivetServer server(cpp_options); // <-- C++ style start

	ExitHandler h_exit;
	server.addHandler(EXIT_URI, h_exit);

#ifdef NO_FILES
	/* This handler will handle "everything else", including
	 * requests to files. If this handler is installed,
	 * NO_FILES should be set. */
	FooHandler h_foo;
	server.addHandler("", h_foo);
#else
	FooHandler h_foo;
	server.addHandler("/.well-known/vanityprime", h_foo);

#endif

	printf("Exit at http://localhost:%s%s\n", PORT, EXIT_URI);

	while (!exitNow) {
#ifdef _WIN32
		Sleep(1000);
#else
		sleep(1);
#endif
	}

	return 0;
}
