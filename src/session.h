
typedef struct Session {
	CK_SESSION_HANDLE handle;

	/* Used during object searches */
	GSList *search_objects, *search_objects_it; 
	gboolean search_on_going;

	GSList *objects_found;
} Session;
