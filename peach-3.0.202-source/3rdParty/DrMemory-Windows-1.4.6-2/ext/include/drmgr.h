/* **********************************************************
 * Copyright (c) 2010-2012 Google, Inc.   All rights reserved.
 * **********************************************************/

/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * * Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 * 
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 * 
 * * Neither the name of Google, Inc. nor the names of its contributors may be
 *   used to endorse or promote products derived from this software without
 *   specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL GOOGLE, INC. OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

/* DynamoRIO Multi-Instrumentation Manager Extension: a mediator for
 * combining and coordinating multiple instrumentation passes
 */

#ifndef _DRMGR_H_
#define _DRMGR_H_ 1

/**
 * @file drmgr.h
 * @brief Header for DynamoRIO Multi-Instrumentation Manager Extension
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \addtogroup drmgr Multi-Instrumentation Manager
 */
/*@{*/ /* begin doxygen group */

/* drmgr replaces the bb event */
#define dr_register_bb_event DO_NOT_USE_bb_event_USE_drmmgr_bb_events_instead
#define dr_unregister_bb_event DO_NOT_USE_bb_event_USE_drmmgr_bb_events_instead

/* drmgr replaces the tls field routines */
#define dr_get_tls_field DO_NOT_USE_tls_field_USE_drmmgr_tls_field_instead
#define dr_set_tls_field DO_NOT_USE_tls_field_USE_drmmgr_tls_field_instead
#define dr_insert_read_tls_field DO_NOT_USE_tls_field_USE_drmmgr_tls_field_instead
#define dr_insert_write_tls_field DO_NOT_USE_tls_field_USE_drmmgr_tls_field_instead

/* drmgr replaces the thread init and exit event and pre-syscall event */
#define dr_register_thread_init_event DO_NOT_USE_thread_event_USE_drmmgr_events_instead
#define dr_unregister_thread_init_event DO_NOT_USE_thread_event_USE_drmmgr_events_instead
#define dr_register_thread_exit_event DO_NOT_USE_thread_event_USE_drmmgr_events_instead
#define dr_unregister_thread_exit_event DO_NOT_USE_thread_event_USE_drmmgr_events_instead
#define dr_register_pre_syscall_event DO_NOT_USE_pre_syscall_USE_drmmgr_events_instead
#define dr_unregister_pre_syscall_event DO_NOT_USE_pre_syscall_USE_drmmgr_events_instead

/***************************************************************************
 * TYPES
 */

/**
 * Callback function for the first and last stages: app2app and instru2instru
 * transformations on the whole instruction list.
 *
 * See #dr_emit_flags_t for an explanation of the return value.  If
 * any instrumentation pass requests DR_EMIT_STORE_TRANSLATIONS, they
 * will be stored.
 */
typedef dr_emit_flags_t (*drmgr_xform_cb_t)
    (void *drcontext, void *tag, instrlist_t *bb, bool for_trace, bool translating);

/**
 * Callback function for the second stage: application analysis.
 *
 * The \p user_data parameter can be used to pass data from this stage
 * to the third stage.
 *
 * See #dr_emit_flags_t for an explanation of the return value.  If
 * any instrumentation pass requests DR_EMIT_STORE_TRANSLATIONS, they
 * will be stored.
 */
typedef dr_emit_flags_t (*drmgr_analysis_cb_t)
    (void *drcontext, void *tag, instrlist_t *bb,
     bool for_trace, bool translating, OUT void **user_data);

/**
 * Callback function for the first stage when using a user data parameter:
 * app2app transformations on instruction list.
 */
typedef drmgr_analysis_cb_t drmgr_app2app_ex_cb_t;

/**
 * Callback function for the second and last stages when using a user
 * data parameter for all four: analysis and instru2instru
 * transformations on the whole instruction list.
 *
 * See #dr_emit_flags_t for an explanation of the return value.  If
 * any instrumentation pass requests DR_EMIT_STORE_TRANSLATIONS, they
 * will be stored.
 */
typedef dr_emit_flags_t (*drmgr_ilist_ex_cb_t)
    (void *drcontext, void *tag, instrlist_t *bb,
     bool for_trace, bool translating, void *user_data);

/**
 * Callback function for the third stage: instrumentation insertion.
 *
 * The \p user_data parameter contains data passed from the second
 * stage to this stage.
 *
 * See #dr_emit_flags_t for an explanation of the return value.  If
 * any instrumentation pass requests DR_EMIT_STORE_TRANSLATIONS, they
 * will be stored.
 */
typedef dr_emit_flags_t (*drmgr_insertion_cb_t)
    (void *drcontext, void *tag, instrlist_t *bb, instr_t *inst,
     bool for_trace, bool translating, void *user_data);

/** Specifies the ordering of callbacks for \p drmgr's events */
typedef struct _drmgr_priority_t {
    /** The size of the drmgr_priority_t struct */
    size_t struct_size;
    /**
     * A name for the callback being registered, to be used by other
     * components when specifying their relative order.
     * This field is mandatory.
     */
    const char *name;
    /**
     * The name of another callback that the callback being registered
     * should precede.  This field is optional and can be NULL.
     */
    const char *before;
    /**
     * The name of another callback that the callback being registered
     * should follow.  This field is optional and can be NULL.
     */
    const char *after;
    /**
     * A numeric priority to resolve identical ordering after the \p before
     * and \p after requests are resolved.  Lower numbers are placed earlier
     * in the callback invocation order.
     */
    int priority;
} drmgr_priority_t;

/***************************************************************************
 * INIT
 */

DR_EXPORT
/**
 * Initializes the drmgr extension.  Must be called prior to any of the
 * other routines, and should only be called once.
 * \return whether successful.  Will return false if called a second time.
 */
bool
drmgr_init(void);

DR_EXPORT
/**
 * Cleans up the drmgr extension.
 */
void
drmgr_exit(void);

/***************************************************************************
 * BB EVENTS
 */

DR_EXPORT
/**
 * Registers a callback function for the first instrumentation stage:
 * application-to-application ("app2app") transformations on each
 * basic block.  drmgr will call \p func as the first of four
 * instrumentation stages for each dynamic application basic block.
 * Examples of app2app transformations include replacing one function
 * with another or replacing one instruction with another throughout
 * an application.
 *
 * The app2app passes are allowed to modify and insert non-meta (i.e.,
 * application) instructions and are intended for application code
 * transformations.  These passes should avoid adding meta
 * instructions other than label instructions.
 *
 * All instrumentation must follow the guidelines for
 * #dr_register_bb_event() with the exception that multiple
 * application control transfer instructions are supported so long as
 * all but one have intra-block \p instr_t targets.  This is to
 * support internal control flow that may be necessary for some
 * application-to-application transformations.  These control transfer
 * instructions should have a translation set so that later passes
 * know which application address they correspond to.  \p drmgr will
 * mark all of the extra non-meta control transfers as meta, and clear
 * their translation fields, right before passing to DynamoRIO, in
 * order to satisfy DynamoRIO's constraints.  This allows all of the
 * instrumentation passes to see these instructions as application
 * instructions, which is how they should be treated.
 *
 * \return false if the given priority request cannot be satisfied
 * (e.g., \p priority->before is already ordered after \p
 * priority->after) or the given name is already taken.
 *
 * @param[in]  func        The callback to be called.
 * @param[in]  priority    Specifies the relative ordering of the callback.
 */
bool
drmgr_register_bb_app2app_event(drmgr_xform_cb_t func, drmgr_priority_t *priority);

DR_EXPORT
/**
 * Unregisters a callback function for the first instrumentation stage.
 * \return true if unregistration is successful and false if it is not
 * (e.g., \p func was not registered).
 *
 * The recommendations for #dr_unregister_bb_event() about when it
 * is safe to unregister apply here as well.
 */
bool
drmgr_unregister_bb_app2app_event(drmgr_xform_cb_t func);

DR_EXPORT
/**
 * Registers callback functions for the second and third
 * instrumentation stages: application analysis and instrumentation
 * insertion.  drmgr will call \p func as the second of four
 * instrumentation stages for each dynamic application basic block.
 *
 * The first stage performed any changes to the original application
 * code, and later stages are not allowed to change application code.
 * Application analysis passes in the second stage are not allowed to
 * add to or change the instruction list other than adding label
 * instructions, and are intended for analysis of application code
 * either for immediate use or for use by the third stage.  Label
 * instructions can be used to store data for use in subsequent stages
 * with custom tags inserted as notes via drmgr_reserve_note_range()
 * and custom data stored via instr_get_label_data_area().
 *
 * The third instrumentation stage is instrumentation insertion.
 * Unlike the other stages, this one passes only one instruction to
 * the callback, allowing each registered component to act on one
 * instruction before moving to the next instruction.  Instrumentation
 * insertion passes are allowed to insert meta instructions only
 * immediately prior to the passed-in instruction: not before any
 * prior non-meta instrution nor after any subsequent non-meta
 * instruction.  They are not allowed to insert new non-meta
 * instructions or change existing non-meta instructions.  Because
 * other components may have alread acted on the instruction list, be
 * sure to ignore already existing meta instructions.
 *
 * The \p analysis_func and \p insertion_func share the same priority.
 * Their user_data parameter can be used to pass data from the
 * analysis stage to the insertion stage.
 *
 * All instrumentation must follow the guidelines for
 * #dr_register_bb_event().
 *
 * \return false if the given priority request cannot be satisfied
 * (e.g., \p priority->before is already ordered after \p
 * priority->after) or the given name is already taken.
 *
 * @param[in]  analysis_func   The analysis callback to be called for the second stage.
 * @param[in]  insertion_func  The insertion callback to be called for the third stage.
 * @param[in]  priority        Specifies the relative ordering of both callbacks.
 */
bool
drmgr_register_bb_instrumentation_event(drmgr_analysis_cb_t analysis_func,
                                        drmgr_insertion_cb_t insertion_func,
                                        drmgr_priority_t *priority);

DR_EXPORT
/**
 * Unregisters \p func and its corresponding insertion
 * callback from the second and third instrumentation stages.
 * \return true if unregistration is successful and false if it is not
 * (e.g., \p func was not registered).
 *
 * The recommendations for #dr_unregister_bb_event() about when it
 * is safe to unregister apply here as well.
 */
bool
drmgr_unregister_bb_instrumentation_event(drmgr_analysis_cb_t func);


DR_EXPORT
/**
 * Registers a callback function for the fourth instrumentation stage:
 * instrumentation-to-instrumentation transformations on each
 * basic block.  drmgr will call \p func as the fourth of four
 * instrumentation stages for each dynamic application basic block.
 * Instrumentation-to-instrumentation passes are allowed to insert meta
 * instructions but not non-meta instructions, and are intended for
 * optimization of prior instrumentation passes.
 *
 * All instrumentation must follow the guidelines for
 * #dr_register_bb_event().
 *
 * \return false if the given priority request cannot be satisfied
 * (e.g., \p priority->before is already ordered after \p
 * priority->after) or the given name is already taken.
 *
 * @param[in]  func        The callback to be called.
 * @param[in]  priority    Specifies the relative ordering of the callback.
 */
bool
drmgr_register_bb_instru2instru_event(drmgr_xform_cb_t func, drmgr_priority_t *priority);

DR_EXPORT
/**
 * Unregisters a callback function for the fourth instrumentation stage.
 * \return true if unregistration is successful and false if it is not
 * (e.g., \p func was not registered).
 *
 * The recommendations for #dr_unregister_bb_event() about when it
 * is safe to unregister apply here as well.
 */
bool
drmgr_unregister_bb_instru2instru_event(drmgr_xform_cb_t func);


DR_EXPORT
/**
 * Registers callbacks for all four instrumentation passes at once, with a \p
 * user_data parameter passed among them all, enabling data sharing for all
 * four.  See the documentation for drmgr_register_bb_app2app_event(),
 * drmgr_register_bb_instrumentation_event(), and
 * drmgr_register_bb_instru2instru_event() for further details of each pass.
 * The aforemented routines are identical to this with the exception of the
 * extra \p user_data parameter, which is an OUT parameter to the \p
 * app2app_func and passed in to the three subsequent callbacks.
 */
bool
drmgr_register_bb_instrumentation_ex_event(drmgr_app2app_ex_cb_t app2app_func,
                                           drmgr_ilist_ex_cb_t analysis_func,
                                           drmgr_insertion_cb_t insertion_func,
                                           drmgr_ilist_ex_cb_t instru2instru_func,
                                           drmgr_priority_t *priority);

DR_EXPORT
/**
 * Unregisters the given four callbacks that
 * were registered via drmgr_register_bb_instrumentation_ex_event().
 * \return true if unregistration is successful and false if it is not
 * (e.g., \p func was not registered).
 *
 * The recommendations for #dr_unregister_bb_event() about when it
 * is safe to unregister apply here as well.
 */
bool
drmgr_unregister_bb_instrumentation_ex_event(drmgr_app2app_ex_cb_t app2app_func,
                                             drmgr_ilist_ex_cb_t analysis_func,
                                             drmgr_insertion_cb_t insertion_func,
                                             drmgr_ilist_ex_cb_t instru2instru_func);

/***************************************************************************
 * TLS
 */

DR_EXPORT
/**
 * Reserves a thread-local storage (tls) slot for every thread.
 * Returns the index of the slot, which should be passed to
 * drmgr_get_tls_field() and drmgr_set_tls_field().  Returns -1 if
 * there are no more slots available.  Each slot is initialized to
 * NULL for each thread and should be properly initialized with
 * drmgr_set_tls_field() in the thread initialization event (see
 * dr_register_thread_init_event()).
 */
int
drmgr_register_tls_field(void);

DR_EXPORT
/**
 * Frees a previously reserved thread-local storage (tls) slot index.
 * Returns false if the slot was not actually reserved.
 */
bool
drmgr_unregister_tls_field(int idx);

DR_EXPORT
/**
 * Returns the user-controlled thread-local-storage field for the
 * given index, which was returned by drmgr_register_tls_field().  To
 * generate an instruction sequence that reads the drcontext field
 * inline in the code cache, use drmgr_insert_read_tls_field().
 */
void *
drmgr_get_tls_field(void *drcontext, int idx);

DR_EXPORT
/** 
 * Sets the user-controlled thread-local-storage field for the
 * given index, which was returned by drmgr_register_tls_field().  To
 * generate an instruction sequence that writes the drcontext field
 * inline in the code cache, use drmgr_insert_write_tls_field().
 * \return whether successful.
 */
bool 
drmgr_set_tls_field(void *drcontext, int idx, void *value);

DR_EXPORT
/**
 * Inserts into \p ilist prior to \p where meta-instruction(s) to read
 * into the general-purpose full-size register \p reg from the
 * user-controlled drcontext field for this thread and index.  Reads
 * from the same field as drmgr_get_tls_field().
 * \return whether successful.
 */
bool
drmgr_insert_read_tls_field(void *drcontext, int idx,
                            instrlist_t *ilist, instr_t *where, reg_id_t reg);

DR_EXPORT
/**
 * Inserts into \p ilist prior to \p where meta-instruction(s) to
 * write the general-purpose full-size register \p reg to the
 * user-controlled drcontext field for this thread and index.  Writes
 * to the same field as drmgr_set_tls_field().  The register \p scratch
 * will be overwritten.
 * \return whether successful.
 */
bool
drmgr_insert_write_tls_field(void *drcontext, int idx,
                             instrlist_t *ilist, instr_t *where, reg_id_t reg,
                             reg_id_t scratch);


/***************************************************************************
 * CLS
 */

DR_EXPORT
/**
 * Reserves a callback-local storage (cls) slot.  Thread-local storage
 * (tls) is callback-shared.  Callbacks interrupt thread execution to
 * execute arbitrary amounts of code in a new context before returning
 * to the interrupted context.  Thread-local storage fields that
 * persist across application execution can be overwritten during
 * callback execution, resulting in incorrect values when returning to
 * the original context.  Callback-local storage, rather than
 * thread-local storage, should be used for any fields that store
 * information specific to the application's execution.
 *
 * Returns the index of the slot, which should be passed to
 * drmgr_get_cls_field() and drmgr_set_cls_field().  Returns -1 if
 * there are no more slots available.
 *
 * Callbacks are frequent, but normally the stack of callback contexts
 * is only a few entries deep.  It is most efficient to re-use cls
 * data from prior callbacks, only allocating new memory when entering
 * a new context stack depth.  The \p cb_init_func parameter is
 * invoked on each new callback context, with \p new_depth set to true
 * only when entering a new callback context stack depth.  When \p
 * new_depth is false, drmgr_get_cls_field() will return the value set
 * at that depth the last time it was reached, and the client would
 * normally not need to allocate memory but would only need to
 * initialize it.  When \p new_depth is true, drmgr_get_cls_field()
 * will return NULL, and the user should use drmgr_set_cls_field() to
 * initialize the slot itself as well as whatever it points to.
 *
 * Similarly, normal usage should ignore \p cb_exit_func unless it is
 * called with \p thread_exit set to true, in which case any memory
 * in the cls slot should be de-allocated.
 *
 * Callbacks are Windows-specific.  The cls interfaces are not marked
 * for Windows-only, however, to facilitate cross-platform code.  We
 * recommend that cross-plaform code be written using cls fields on
 * both platforms; the fields on Linux will never be stacked and will
 * function as tls fields.  Technically the same context interruption
 * can occur with a Linux signal, but Linux signals typically execute
 * small amounts of code and avoid making stateful changes;
 * furthermore, there is no guaranteed end point to a signal.  The
 * drmgr_push_cls() and drmgr_pop_cls() interface can be used to
 * provide a stack of contexts on Linux, or to provide a stack of
 * contexts for any other purpose such as layered wrapped functions.
 * These push and pop functions are automatically called on Windows
 * callback entry and exit.
 */
int
drmgr_register_cls_field(void (*cb_init_func)(void *drcontext, bool new_depth),
                         void (*cb_exit_func)(void *drcontext, bool thread_exit));

DR_EXPORT
/**
 * Frees a previously reserved callback-local storage (cls) slot index and
 * unregisters its event callbacks.
 * Returns false if the slot was not actually reserved.
 */
bool
drmgr_unregister_cls_field(void (*cb_init_func)(void *drcontext, bool new_depth),
                           void (*cb_exit_func)(void *drcontext, bool thread_exit),
                           int idx);

DR_EXPORT
/**
 * Returns the user-controlled callback-local-storage field for the
 * given index, which was returned by drmgr_register_cls_field().  To
 * generate an instruction sequence that reads the drcontext field
 * inline in the code cache, use drmgr_insert_read_cls_field().
 */
void *
drmgr_get_cls_field(void *drcontext, int idx);

DR_EXPORT
/** 
 * Sets the user-controlled callback-local-storage field for the
 * given index, which was returned by drmgr_register_cls_field().  To
 * generate an instruction sequence that writes the drcontext field
 * inline in the code cache, use drmgr_insert_write_cls_field().
 * \return whether successful.
 */
bool 
drmgr_set_cls_field(void *drcontext, int idx, void *value);

DR_EXPORT
/**
 * Inserts into \p ilist prior to \p where meta-instruction(s) to read
 * into the general-purpose full-size register \p reg from the
 * user-controlled drcontext field for the current (at
 * execution time) callback and index.  Reads from the same field as
 * drmgr_get_cls_field().
 * \return whether successful.
 */
bool
drmgr_insert_read_cls_field(void *drcontext, int idx,
                            instrlist_t *ilist, instr_t *where, reg_id_t reg);

DR_EXPORT
/**
 * Inserts into \p ilist prior to \p where meta-instruction(s) to
 * write the general-purpose full-size register \p reg to the
 * user-controlled drcontext field for the current (at execution time)
 * callback and index.  Writes to the same field as
 * drmgr_set_cls_field().  The register \p scratch will be
 * overwritten.
 * \return whether successful.
 */
bool
drmgr_insert_write_cls_field(void *drcontext, int idx,
                             instrlist_t *ilist, instr_t *where, reg_id_t reg,
                             reg_id_t scratch);

DR_EXPORT
/**
 * Pushes a new callback context onto the callback-local storage (cls)
 * context stack for the given thread.  This function is automatically
 * called on entry to a new Windows callback.  Users can invoke it to
 * provide context stacks for their own uses, including Linux signals
 * or layered wrapped functions.  Invoking this function will trigger
 * the \p cb_init_func passed to drmgr_register_cls_field().
 * \return whether successful.
 */
bool
drmgr_push_cls(void *drcontext);

DR_EXPORT
/**
 * Pops a callback context from the callback-local storage (cls)
 * context stack for the given thread.  This function is automatically
 * called on exit from a Windows callback.  Users can invoke it to
 * provide context stacks for their own uses, including Linux signals
 * or layered wrapped functions.  Invoking this function will trigger
 * the \p cb_exit_func passed to drmgr_register_cls_field().
 *
 * Returns false if the context stack has only one entry.
 */
bool
drmgr_pop_cls(void *drcontext);


/***************************************************************************
 * INSTRUCTION NOTE FIELD
 */

enum {
    DRMGR_NOTE_NONE,
};

DR_EXPORT
/**
 * Reserves \p size values in the namespace for use in the \p note
 * field of instructions.  The reserved range starts at the return
 * value and is contiguous.  Returns DRMGR_NOTE_NONE on failure.
 * Un-reserving is not supported.
 */
ptr_uint_t
drmgr_reserve_note_range(size_t size);

/***************************************************************************
 * UTILITIES
 */

#ifdef WINDOWS
DR_EXPORT
/**
 * Given a system call wrapper routine \p entry of the Native API variety,
 * decodes the routine and returns the system call number.
 */
int
drmgr_decode_sysnum_from_wrapper(app_pc entry);
#endif

/***************************************************************************
 * DR EVENT REPLACEMENTS WITH NO SEMANTIC CHANGES
 */

DR_EXPORT
/**
 * Registers a callback function for the thread initialization event.
 * drmgr calls \p func whenever the application creates a new thread.
 * \return whether successful.
 */
bool
drmgr_register_thread_init_event(void (*func)(void *drcontext));

DR_EXPORT
/**
 * Unregister a callback function for the thread initialization event.
 * \return true if unregistration is successful and false if it is not
 * (e.g., \p func was not registered).
 */
bool
drmgr_unregister_thread_init_event(void (*func)(void *drcontext));

DR_EXPORT
/**
 * Registers a callback function for the thread exit event.  drmgr calls \p func
 * whenever DR would, when an application thread exits.  All the constraints of
 * dr_register_thread_exit_event() apply.  \return whether successful.
 */
bool
drmgr_register_thread_exit_event(void (*func)(void *drcontext));

DR_EXPORT
/**
 * Unregister a callback function for the thread exit event.
 * \return true if unregistration is successful and false if it is not
 * (e.g., \p func was not registered).
 */
bool
drmgr_unregister_thread_exit_event(void (*func)(void *drcontext));

DR_EXPORT
/**
 * Registers a callback function for the pre-syscall event, which
 * behaves just like DR's pre-syscall event
 * dr_register_pre_syscall_event().
 * \return whether successful.
 */
bool
drmgr_register_pre_syscall_event(bool (*func)(void *drcontext, int sysnum));

DR_EXPORT
/**
 * Unregister a callback function for the pre-syscall event.
 * \return true if unregistration is successful and false if it is not
 * (e.g., \p func was not registered).
 */
bool
drmgr_unregister_pre_syscall_event(bool (*func)(void *drcontext, int sysnum));


/*@}*/ /* end doxygen group */

#ifdef __cplusplus
}
#endif

#endif /* _DRMGR_H_ */
