#define OPAQUE_SPECIAL_TYPES
#define MAX_OID_LEN  128

typedef u_long oid;

struct variable_list {
    struct variable_list *next_variable;    /* NULL for last variable */
    oid	    *name;  /* Object identifier of variable */
    size_t  name_length;    /* number of subid's in name */
    u_char  type;   /* ASN type of variable */
    union { /* value of variable */
	long	*integer;
	u_char	*string;
	oid	*objid;
	u_char  *bitstring;
	struct counter64 *counter64;
#ifdef OPAQUE_SPECIAL_TYPES
	float   *floatVal;
	double	*doubleVal;
/*	t_union *unionVal; */
#endif /* OPAQUE_SPECIAL_TYPES */
    } val;
    size_t	    val_len;
    oid name_loc[MAX_OID_LEN];  /* 90 percentile < 24. */
    u_char buf[40];             /* 90 percentile < 40. */
    void *data;			/* (Opaque) hook for additional data */
    void (*dataFreeHook)(void *);	/* callback to free above */
    int  index;
};

