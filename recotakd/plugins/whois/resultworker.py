import threading
import Queue
# Copyright (c) 2014, curesec GmbH
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without modification, 
# are permitted provided that the following conditions are met:
# 
# 1. Redistributions of source code must retain the above copyright notice, this list of 
# conditions and the following disclaimer.
# 
# 2. Redistributions in binary form must reproduce the above copyright notice, this list 
# of conditions and the following disclaimer in the documentation and/or other materials 
# provided with the distribution.
# 
# 3. Neither the name of the copyright holder nor the names of its contributors may be used 
# to endorse or promote products derived from this software without specific prior written 
# permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS 
# OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE 
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, 
# EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) 
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR 
# TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, 
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
import logging
import __builtin__
import thread

from whoisxml import Xml

logger = logging.getLogger(__name__)

class Worker(threading.Thread):
    """ base class """

    def __init__(self, filename=None):
        threading.Thread.__init__(self)
        self.stop_event = threading.Event()
        self.filename = filename

    def stop(self):
        logger.debug("received stop signal")
        self.stop_event.set()

    def run(self):
        """ overwritten """
        pass

class XmlWorker(Worker):
    """ stores in xml format """

    def run(self):
        xml = Xml()

        try:
            # run until a stop event is received
            while not self.stop_event.isSet():

                # wait maximal 1 second for an element
                # otherwise raise 'empty' exception
                try:
                    responseType, name, query, result = XmlWorker.Results.get(True,1)
                except (Queue.Empty, EOFError):
                    # If no element is available, continue.
                    # Though, it check whether thread is
                    # needed.
                    continue

                logger.debug("processing result %s" % \
                        (name))

                # build xml request node
                queryResultNode = xml.addQueryResult(name, responseType)

                # add query node
                xml.addQuery(queryResultNode, query)

                # add result node
                if (result != None):
                    node = xml.addResponse(queryResultNode, result)

                XmlWorker.Results.task_done()

                logger.debug("---------")
                xml.save(self.filename)
                logger.debug("successfully saved")


        except Exception as err:
            raise err

        logger.debug('xmlWorker is finished - so exiting run method')

class NetnameWorker(Worker):
    """ stores netnames in txt file """

    def run(self):
        if self.filename:
            f = __builtin__.openany(self.filename, "w")
        else:
            f = None

        try:

            # run until a stop event is received
            while not self.stop_event.isSet():

                # wait maximal 1 second for an element
                # otherwise raise 'empty' exception
                try:
                    netname = NetnameWorker.Results.get(True,1)
                except (Queue.Empty, EOFError):
                    # If no element is available, continue.
                    # Though, it check whether thread is
                    # needed.
                    continue

                logger.debug("writing %s to file.." % netname)
                f.write(netname + "\n")

                NetnameWorker.Results.task_done()

        except EOFError:
            pass

        except Exception as err:
            raise err

        finally:
            if f:
                f.close()

        logger.debug('netnameWorker is finished - so exiting run method')

class TxtWorker(Worker):
    """ stores results in txt file """

    def run(self):
        f = __builtin__.openany(self.filename, "w")

        try:

            # run until a stop event is received
            while not self.stop_event.isSet():

                # wait maximal 1 second for an element
                # otherwise raise 'empty' exception
                try:
                    ip = TxtWorker.Results.get(True,1)
                except (Queue.Empty, EOFError):
                    # If no element is available, continue.
                    # Though, it check whether thread is
                    # needed.
                    continue

                logger.debug("writing %s to file.." % ip)
                ip_clean = ip.replace(" ","")
                #f.write(ip_clean + "\n")
                print(ip_clean)
                TxtWorker.Results.task_done()

        except EOFError:
            pass

        except Exception as err:
            raise err

        finally:
            f.close()

        logger.debug('txtWorker is finished - so exiting run method')
