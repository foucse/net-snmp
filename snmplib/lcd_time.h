/*
 * lcd_time.h
 */

#ifndef _LCD_TIME_H
#define _LCD_TIME_H

#ifndef TRUE
#define TRUE (!0)
#endif

#ifndef FALSE
#define FALSE !(TRUE)
#endif




/*
 * Macros and definitions.
 */
#define ETIMELIST_SIZE	23

#define SET_HASH_TRANSFORM(t)	kmt_hash = t;

#define ENGINETIME_MAX	((2^31)-1)
#define ENGINEBOOT_MAX	((2^31)-1)	/* XXX	Perhaps these two deserve
					 *	a more conspicuous location?
					 */


typedef struct enginetime_struct {
	u_char		*engineID;	
	u_int		 engineID_len;

	u_int		 engineTime;	
	u_int		 engineBoot;
		/* Time & boots values received from last authenticated
		 *   message within the previous time window.
		 */

	time_t		 lastReceivedEngineTime;
		/* Timestamp made when engineTime/engineBoots was last
		 *   updated.  Measured in seconds.
		 */

	struct enginetime_struct	*next;
} enginetime, *Enginetime;




/*
 * Macros for streamlined engineID existence checks --
 *
 *	e	is char *engineID,
 *	e_l	is u_int engineID_len.
 *
 *
 *  ISENGINEKNOWN(e, e_l)
 *	Returns:
 *		TRUE	If engineID is recoreded in the EngineID List;
 *		FALSE	Otherwise.
 *
 *  ENSURE_ENGINE_RECORD(e, e_l)
 *	Adds the given engineID to the EngineID List if it does not exist
 *		already.  engineID is added with a <enginetime, engineboots>
 *		tuple of <0,0>.  Always succeeds -- except in case of a
 *		fatal internal error.
 *	Returns:
 *		SNMPERR_SUCCESS	On success;
 *		SNMPERR_GENERR	Otherwise.
 *
 *  MAKENEW_ENGINE_RECORD(e, e_l)
 *	Returns:
 *		SNMPERR_SUCCESS	If engineID already exists in the EngineID List;
 *		SNMPERR_GENERR	Otherwise -and- invokes ENSURE_ENGINE_RECORD()
 *					to add an entry to the EngineID List.
 */
static u_int	dummy_etime, dummy_eboot;

#define ISENGINEKNOWN(e, e_l)					\
	( (get_enginetime(e, e_l,				\
		&dummy_etime, &dummy_eboot) == SNMPERR_SUCCESS)	\
		? TRUE						\
		: FALSE )

#define ENSURE_ENGINE_RECORD(e, e_l)				\
	( (set_enginetime(e, e_l, 0, 0) == SNMPERR_SUCCESS)	\
		? SNMPERR_SUCCESS				\
		: SNMPERR_GENERR )

#define MAKENEW_ENGINE_RECORD(e, e_l)				\
	( (ISENGINEKNOWN(e, e_l))				\
		? SNMPERR_SUCCESS				\
		: ENSURE_ENGINE_RECORD(e, e_l), SNMPERR_GENERR )



/*
 * Prototypes.
 */
int	 get_enginetime __P((	u_char	*engineID,	u_int  engineID_len,
				u_int	*enginetime,	u_int *engineboot
			    ));

int	 set_enginetime __P((	u_char *engineID,	u_int engineID_len,
				u_int   enginetime,	u_int engineboot
			    ));

Enginetime
	 search_enginetime_list __P((	u_char		*engineID,
					u_int		 engineID_len));

int	 hash_engineID __P((u_char *engineID, u_int engineID_len));

void	 dump_etimelist_entry __P((void));

#endif /* _LCD_TIME_H */

