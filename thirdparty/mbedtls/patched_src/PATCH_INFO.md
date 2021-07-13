## Patched MbedTLS version:  v2.26.0

## Patch 1 - Add Windows Threading

### File `check_config.h`

```c
// --------------------------------------------------------------------------
//  Added by Virgil Security, Inc.
#if defined(MBEDTLS_THREADING_SRWLOCK)
#if !defined(MBEDTLS_THREADING_C) || defined(MBEDTLS_THREADING_IMPL)
#error "MBEDTLS_THREADING_PTHREAD defined, but not all prerequisites"
#endif
#define MBEDTLS_THREADING_IMPL
#endif
// --------------------------------------------------------------------------
```

### File `threading.h`

```c
// --------------------------------------------------------------------------
//  Added by Virgil Security, Inc.
#if defined(MBEDTLS_THREADING_SRWLOCK)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <synchapi.h>
#undef WIN32_LEAN_AND_MEAN
typedef struct mbedtls_threading_mutex_t
{
    SRWLOCK lock;
} mbedtls_threading_mutex_t;
#endif
// --------------------------------------------------------------------------
```

### File `threading.c`

```c
// --------------------------------------------------------------------------
//  Added by Virgil Security, Inc.
#if defined(MBEDTLS_THREADING_SRWLOCK)
static void threading_mutex_init_pthread( mbedtls_threading_mutex_t *mutex )
{
    if( mutex == NULL )
        return;

   InitializeSRWLock( &mutex->lock );
}

static void threading_mutex_free_pthread( mbedtls_threading_mutex_t *mutex )
{
    if( mutex == NULL )
        return;

    /*
     * SRW locks do not need to be explicitly destroyed.
     */
}

static int threading_mutex_lock_pthread( mbedtls_threading_mutex_t *mutex )
{
    if( mutex == NULL )
        return( MBEDTLS_ERR_THREADING_BAD_INPUT_DATA );

    AcquireSRWLockExclusive( &mutex->lock );

    return( 0 );
}

static int threading_mutex_unlock_pthread( mbedtls_threading_mutex_t *mutex )
{
    if( mutex == NULL )
        return( MBEDTLS_ERR_THREADING_BAD_INPUT_DATA );

    ReleaseSRWLockExclusive( &mutex->lock );

    return( 0 );
}

void (*mbedtls_mutex_init)( mbedtls_threading_mutex_t * ) = threading_mutex_init_pthread;
void (*mbedtls_mutex_free)( mbedtls_threading_mutex_t * ) = threading_mutex_free_pthread;
int (*mbedtls_mutex_lock)( mbedtls_threading_mutex_t * ) = threading_mutex_lock_pthread;
int (*mbedtls_mutex_unlock)( mbedtls_threading_mutex_t * ) = threading_mutex_unlock_pthread;

/*
 * With SRW Lock we can statically initialize mutexes
 */
#define MUTEX_INIT  = SRWLOCK_INIT

#endif /* MBEDTLS_THREADING_SRWLOCK */
// --------------------------------------------------------------------------
```

