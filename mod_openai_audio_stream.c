/*
 * Openai mod_openai_audio_stream FreeSWITCH module to stream audio to websocket and receive responses from OpenAI Realtime API.
 */
#include "mod_openai_audio_stream.h"
#include "openai_audio_streamer_glue.h"
#include <strings.h>

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_openai_audio_stream_shutdown);
SWITCH_MODULE_RUNTIME_FUNCTION(mod_openai_audio_stream_runtime);
SWITCH_MODULE_LOAD_FUNCTION(mod_openai_audio_stream_load);

SWITCH_MODULE_DEFINITION(mod_openai_audio_stream, mod_openai_audio_stream_load, mod_openai_audio_stream_shutdown, NULL /*mod_openai_audio_stream_runtime*/);

static void responseHandler(switch_core_session_t* session, const char* eventName, const char* json) {
    switch_event_t *event;
    switch_channel_t *channel = switch_core_session_get_channel(session);
    switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, eventName);
    switch_channel_event_set_data(channel, event);
    if (json) switch_event_add_body(event, "%s", json);
    switch_event_fire(&event);
}

static switch_bool_t capture_callback(switch_media_bug_t *bug, void *user_data, switch_abc_type_t type)
{
    switch_core_session_t *session = switch_core_media_bug_get_session(bug);
    private_t *tech_pvt = (private_t *)user_data;

    switch (type) {
        case SWITCH_ABC_TYPE_INIT:
            break;

        case SWITCH_ABC_TYPE_CLOSE:
            {
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "Got SWITCH_ABC_TYPE_CLOSE.\n"); 

                // Check if this is a normal channel closure or a requested closure
                int channelIsClosing = tech_pvt->close_requested ? 0 : 1;
                stream_session_cleanup(session, NULL, channelIsClosing);
            }
            break;

        case SWITCH_ABC_TYPE_READ:
            if (tech_pvt->close_requested) {
                return SWITCH_FALSE;
            }
            return stream_frame(bug);
            break;
        case SWITCH_ABC_TYPE_WRITE_REPLACE: //This is where the mediabug will write audio data to the channel
            if (tech_pvt->close_requested) { 
                return SWITCH_FALSE;
            }
            write_frame(session, bug);
            break;

        case SWITCH_ABC_TYPE_WRITE:
        default:
            break;
    }

    return SWITCH_TRUE;
}

static switch_status_t start_capture(switch_core_session_t *session,
                                     switch_media_bug_flag_t flags,
                                     char* wsUri,
                                     int sampling)
{
    switch_channel_t *channel = switch_core_session_get_channel(session);
    switch_media_bug_t *bug;
    switch_status_t status;
    switch_codec_t* read_codec;

    void *pUserData = NULL;
    int channels = (flags & SMBF_STEREO) ? 2 : 1;

    if (switch_channel_get_private(channel, MY_BUG_NAME)) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "mod_openai_audio_stream: bug already attached!\n");
        return SWITCH_STATUS_FALSE;
    }

    if (switch_channel_pre_answer(channel) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "mod_openai_audio_stream: channel must have reached pre-answer status before calling start!\n");
        return SWITCH_STATUS_FALSE;
    }

    read_codec = switch_core_session_get_read_codec(session);

    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "calling stream_session_init.\n");
    if (SWITCH_STATUS_FALSE == stream_session_init(session, responseHandler, read_codec->implementation->actual_samples_per_second,
                                                 wsUri, sampling, channels, &pUserData)) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "Error initializing mod_openai_audio_stream session.\n");
        return SWITCH_STATUS_FALSE;
    }
    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "adding bug.\n");
    if ((status = switch_core_media_bug_add(session, MY_BUG_NAME, NULL, capture_callback, pUserData, 0, flags, &bug)) != SWITCH_STATUS_SUCCESS) {
        return status;
    }
    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "setting bug private data.\n");
    switch_channel_set_private(channel, MY_BUG_NAME, bug);

    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "exiting start_capture.\n");
    return SWITCH_STATUS_SUCCESS;
}

static switch_status_t do_stop(switch_core_session_t *session, char* json)
{
    switch_status_t status = SWITCH_STATUS_SUCCESS;

    if (json) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "mod_openai_audio_stream: stop w/ final json %s\n", json);
    }
    else {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "mod_openai_audio_stream: stop\n");
    }
    status = stream_session_cleanup(session, json, 0);

    return status;
}

static switch_status_t do_pauseresume(switch_core_session_t *session, int pause)
{
    switch_status_t status = SWITCH_STATUS_SUCCESS;

    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "mod_openai_audio_stream: %s\n", pause ? "pause" : "resume");
    status = stream_session_pauseresume(session, pause);

    return status;
}

static switch_status_t send_json(switch_core_session_t *session, char* json) {
    switch_status_t status = SWITCH_STATUS_FALSE;
    switch_channel_t *channel = switch_core_session_get_channel(session);
    switch_media_bug_t *bug = switch_channel_get_private(channel, MY_BUG_NAME);

    if (bug) {
        status = stream_session_send_json(session, json);
    }
    else {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "mod_openai_audio_stream: no bug, failed sending json\n");
    }
    return status;
}

#define STREAM_API_SYNTAX "<uuid> [start | stop | send_json | pause | resume | graceful-shutdown ] [wss-url | path] [mono | mixed | stereo] [8000 | 16000 | 24000]"
SWITCH_STANDARD_API(stream_function)
{
    char *mycmd = NULL, *argv[6] = { 0 };
    int argc = 0;

    switch_status_t status = SWITCH_STATUS_FALSE;

    if (!zstr(cmd) && (mycmd = strdup(cmd))) {
        argc = switch_separate_string(mycmd, ' ', argv, (sizeof(argv) / sizeof(argv[0])));
    }
    assert(cmd);

    if (zstr(cmd) || argc < 2 || (0 == strcmp(argv[1], "start") && argc < 4)) {
        switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "Error with command %s.\n", cmd);
        stream->write_function(stream, "-USAGE: %s\n", STREAM_API_SYNTAX);
        goto done;
    } else {
        if (strcasecmp(argv[1], "send_json")) { 
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "mod_openai_audio_stream cmd: %s\n", cmd ? cmd : "");
        }
        switch_core_session_t *lsession = NULL;
        if ((lsession = switch_core_session_locate(argv[0]))) {
            if (!strcasecmp(argv[1], "stop")) {
                if(argc > 2 && (is_valid_utf8(argv[2]) != SWITCH_STATUS_SUCCESS)) {
                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR,
                                      "%s contains invalid utf8 characters\n", argv[2]);
                    switch_core_session_rwunlock(lsession);
                    goto done;
                }
                status = do_stop(lsession, argc > 2 ? argv[2] : NULL);
            } else if (!strcasecmp(argv[1], "pause")) {
                status = do_pauseresume(lsession, 1);
            } else if (!strcasecmp(argv[1], "resume")) {
                status = do_pauseresume(lsession, 0);
            } else if (!strcasecmp(argv[1], "send_json")) {
                if (argc < 3) {
                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR,
                                      "send_json requires an argument specifying json to send\n");
                    switch_core_session_rwunlock(lsession);
                    goto done;
                }
                status = send_json(lsession, argv[2]);
            } else if (!strcasecmp(argv[1], "start")) {
                //switch_channel_t *channel = switch_core_session_get_channel(lsession);
                char wsUri[MAX_WS_URI];
                int sampling = 8000;
                switch_media_bug_flag_t flags = SMBF_READ_STREAM;
                flags |= SMBF_WRITE_REPLACE;
                if (0 == strcmp(argv[3], "mixed")) {
                    flags |= SMBF_WRITE_STREAM;
                } else if (0 == strcmp(argv[3], "stereo")) {
                    flags |= SMBF_WRITE_STREAM;
                    flags |= SMBF_STEREO;
                } else if (0 != strcmp(argv[3], "mono")) {
                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR,
                                      "invalid mix type: %s, must be mono, mixed, or stereo\n", argv[3]);
                    switch_core_session_rwunlock(lsession);
                    goto done;
                }
                if (argc > 4) {
                    if (0 == strcmp(argv[4], "16k")) {
                        sampling = 16000;
                    } else if (0 == strcmp(argv[4], "8k")) {
                        sampling = 8000;
                    } else if (0 == strcmp(argv[4], "24k")) {
                        sampling = 24000;
                    } else {
                        sampling = atoi(argv[4]);
                    }
                }

                if (!validate_ws_uri(argv[2], &wsUri[0])) {
                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR,
                                      "invalid websocket uri: %s\n", argv[2]);
                } else if (sampling % 8000 != 0) {
                    switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR,
                                      "invalid sample rate: %s\n", argv[4]);
                } else {
                    status = start_capture(lsession, flags, wsUri, sampling);
                }
            } else {
                switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR,
                                  "unsupported mod_openai_audio_stream cmd: %s\n", argv[1]);
            }


            switch_core_session_rwunlock(lsession);
        } else {
            switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "Error locating session %s\n",
                              argv[0]);
        }
    }

    if (status == SWITCH_STATUS_SUCCESS) {
        stream->write_function(stream, "+OK Success\n");
    } else {
        stream->write_function(stream, "-ERR Operation Failed\n");
    }

done:
    switch_safe_free(mycmd);
    return SWITCH_STATUS_SUCCESS;
}

SWITCH_MODULE_LOAD_FUNCTION(mod_openai_audio_stream_load)
{
    switch_api_interface_t *api_interface;

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "mod_openai_audio_stream API loading..\n");

    /* connect my internal structure to the blank pointer passed to me */
    *module_interface = switch_loadable_module_create_module_interface(pool, modname);

    /* create/register custom event message types */
    if (switch_event_reserve_subclass(EVENT_JSON) != SWITCH_STATUS_SUCCESS ||
        switch_event_reserve_subclass(EVENT_CONNECT) != SWITCH_STATUS_SUCCESS ||
        switch_event_reserve_subclass(EVENT_ERROR) != SWITCH_STATUS_SUCCESS ||
        switch_event_reserve_subclass(EVENT_DISCONNECT) != SWITCH_STATUS_SUCCESS ||
        switch_event_reserve_subclass(EVENT_OPENAI_SPEECH_STARTED) != SWITCH_STATUS_SUCCESS ||
        switch_event_reserve_subclass(EVENT_OPENAI_SPEECH_STOPPED) != SWITCH_STATUS_SUCCESS) {
        switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Couldn't register an event subclass for mod_openai_audio_stream API.\n");
        return SWITCH_STATUS_TERM;
    }
    SWITCH_ADD_API(api_interface, "uuid_openai_audio_stream", "audio_stream API", stream_function, STREAM_API_SYNTAX);
    switch_console_set_complete("add uuid_openai_audio_stream ::console::list_uuid start wss-url");
    switch_console_set_complete("add uuid_openai_audio_stream ::console::list_uuid stop");
    switch_console_set_complete("add uuid_openai_audio_stream ::console::list_uuid pause");
    switch_console_set_complete("add uuid_openai_audio_stream ::console::list_uuid resume");
    switch_console_set_complete("add uuid_openai_audio_stream ::console::list_uuid send_json");

    switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_NOTICE, "mod_openai_audio_stream API successfully loaded\n");

    /* indicate that the module should continue to be loaded */
    return SWITCH_STATUS_SUCCESS;
}

/*
  Called when the system shuts down
  Macro expands to: switch_status_t mod_openai_audio_stream_shutdown() */
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_openai_audio_stream_shutdown)
{
    switch_event_free_subclass(EVENT_JSON);
    switch_event_free_subclass(EVENT_CONNECT);
    switch_event_free_subclass(EVENT_DISCONNECT);
    switch_event_free_subclass(EVENT_ERROR);
    switch_event_free_subclass(EVENT_OPENAI_SPEECH_STARTED);
    switch_event_free_subclass(EVENT_OPENAI_SPEECH_STOPPED);

    return SWITCH_STATUS_SUCCESS;
}
