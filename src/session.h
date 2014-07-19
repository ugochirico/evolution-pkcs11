
typedef struct Session {
	CK_SESSION_HANDLE handle;

	/* Used during object searches */
	GSList *cursor_list, *current_cursor;
	gboolean search_on_going;

	/* Objects that the session knows */
	GSList *objects_found;
} Session;
