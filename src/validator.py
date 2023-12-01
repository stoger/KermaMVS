import objects
import time
import asyncio

# coroutine that will start another coroutine after a delay in seconds
async def delay(coro, seconds):
    # suspend for a time limit in seconds
    await asyncio.sleep(seconds)
    # execute the other coroutine
    print('Timeout triggered')
    coro()

class Validator:

    def __init__(self):
        self.pending_objects = {}

    #whenever thread receives block with unkown transactions invoke fetch, and call this
    def verification_pending(self, obj, thread, unknown_objects):
        print(f'New verification pending for object {obj}')
        self.pending_objects[objects.get_objid(obj)] = {
            'object' : obj,
            'queue' : thread,
            'unknown_objects' : unknown_objects,
            'timeout' : time.time() + 5
        }
        asyncio.create_task(delay(self.timeout, 5))

    def timeout(self):
        for key in self.pending_objects.copy().keys():
            o = self.pending_objects[key]
            if o['timeout'] < time.time():
                #invalidate this
                o['queue'].put_nowait({
                    'type' : 'error',
                    'name' : 'UNFINDABLE_OBJECT',
                    'msg' : 'Timeout triggered'
                })
                self.pending_objects.pop(key)
                self.new_invalid_object(key)

    ##whenever new object recceived handle_connection calls this --> not yet required
    #def received_object(self, objid):

    #whenever a thread validated a new object
    def new_valid_object(self, objid):
        for key in self.pending_objects.copy().keys():
            o = self.pending_objects[key]
            unknown_objects = o['unknown_objects']
            if objid in unknown_objects:
                unknown_objects.remove(objid)
                if len(unknown_objects) == 0:
                    self.pending_objects.pop(key)
                    #send this into the thread queue
                    try:
                        o['queue'].put_nowait({
                            'type' : 'resumeValidation', #this is a special type to tell the thread to restart validation
                            'object': o['object'],
                        })
                    except Exception:
                        pass

    def new_invalid_object(self, objid):
        for key in self.pending_objects.copy().keys():
            o = self.pending_objects[key]
            unknown_objects = o['unknown_objects']
            if objid in unknown_objects:
                #this object is invalid
                #send this into the thread queue
                try:
                    o['thread'].put_nowait({
                        'msg': f"Object {key} depends on invalid object {objid}",
                        'name': "INVALID_ANCESTRY"
                    })
                    #TODO: propagate this errror
                    self.pending_objects.pop(key)
                    self.new_invalid_object(key)
                except Exception:
                    pass


