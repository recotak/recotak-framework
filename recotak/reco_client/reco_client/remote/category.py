"""
stub of the ccd category.
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

A category to a remote.plugin equals the directory to file relation. The wordings
"category" and "directory" are used both and mean the same. The user is able to
traverse over categories, like he is able to move through directories.

Every category might have arbitrary subcategories.

"""

import reco_client.connection.comm as comm
import reco_client.core.errors as errors
import reco_client.remote as remote
from copy import copy
import logging
logger = logging.getLogger("client.%s" % __name__)

SYMBOL_PREVDIR = ".."
SYMBOL_ROOTDIR = ""

class RemoteCategory(object):
    """
    the category stub that handles category operations which were sent to ccd.

    a remote category has the following attributes:

        id      id of the category, int
        name    name of the category
        session a client session

    """

    def __init__(self, id, name, session):
        self.id = int(id)
        self.name = name
        self._content = None
        self.session = session

    def _reload(self):
        """
        reload the category's content. To do so, call comm.sendpacket and parse
        response.

        input:
            comm.sendpacket  callback function to call for ccd request

        """
        content = []
        resp_t = comm.sendpacket(self.session, op=comm.ccdlib.OP_GETCAT, cat=self.id)

        try:
            for rc in resp_t[-1]:
                # remote.plugin
                if rc["isplugin"]:
                    content += [remote.plugin.RemotePlugin(
                        id=rc["id"],
                        grpid=rc["conngroup"],
                        session=self.session,
                        help=rc["help"],
                        name=(rc["name"] +
                              remote.plugin.RemotePlugin.EXTENSION)
                    )]
                # category
                else:
                    content += [RemoteCategory(id=rc["id"],
                                               name=rc["name"],
                                               session=self.session)]

        except KeyError:
            raise Exception("Unprober json format for remote "
                            "categories' content")

        self._content = content

    def listContent(self, force_reload=False):
        if self._content is None or force_reload:
            self._reload()
        return self._content

    def __contains__(self, name):
        if self._content is None:
            self._reload()

        for c in self._content:
            if c.name == name:
                r = True
                break
        else:
            r = False

        return r

def changedir(session, dst):
    """
    changes directory. It gets a path to a dir and traverses it.

    input:
        session session object that is affected by directory change
        dst     destination to change to. the destination is either of type
                string that represents a path or it is of type
                argparse.Namespace. In case of the latter one, dst is
                extraced from the Namespace

    """
    tmp_cat = copy(session.current_category)
    tmp_history = copy(session.history)
    path = copy(dst.rstrip("/").split("/"))
    try:
        for idx, _subcat in enumerate(path):
            if _subcat == SYMBOL_ROOTDIR:
                if idx != 0:
                    raise errors.NotFoundError()
                tmp_cat = RemoteCategory(id=0, name="/", session=session)
                tmp_history = []

            elif _subcat == SYMBOL_PREVDIR:
                try:
                    tmp_history.pop()

                    if tmp_history:
                        tmp_cat = tmp_history[-1]
                    else:
                        tmp_cat = RemoteCategory(id=0,
                                                 name="/",
                                                 session=session)
                except IndexError:
                    pass

            else:
                cats = tmp_cat.listContent()
                for cat in cats:
                    if (_subcat == cat.name and
                            isinstance(cat, RemoteCategory)):
                        tmp_cat = cat
                        tmp_history.append(cat)
                        break
                else:
                    raise errors.NotFoundError()

    except:
        raise errors.NotFoundError("No such category: %s!" % repr(dst))

    session.current_category = tmp_cat
    session.history = tmp_history


def listplugins(session,
                cat,
                r=True,
                force_reload=False):
    """
    lists current categorie's content. It is possible to only show
    plugins or/and categories. If r is True, then show recurively
    everthing within the subdirs.

    input:
        cat         category to show content of
        showPlg     boolean to indicate whether to show plugins
        showCat     boolean to indicate whether to show categories
        r           boolean to indicate to scan recursively
        l           boolean to indicate that details are requested too
        force_reload    boolean to trigger reloading of remote content

    ouput:
        content     a list of the categories content

    """
    content = []

    # if we changed something (e.g. updating groups) we want the client to
    # fetch the update even if the user did not explicitly asks for
    try:
        force_reload = listdir.update_happened
    except AttributeError:
        pass

    # request content
    try:
        response = cat.listContent(force_reload)
    except Exception as e:
        print(e)
        if not session.project:
            return []
        else:
            response = []

    # iterate over all categories, respectively plugins. every category has
    # at least an identifier and a name.
    for c in response:
        if isinstance(c, remote.plugin.RemotePlugin):
            content.append(c)

        elif r and isinstance(c, RemoteCategory):
            content.extend(listplugins(session, c, r))

    return content


def listdir(session, cat, showPlg=True, showCat=True, r=False, l=False,
            force_reload=False):
    """
    lists current categorie's content. It is possible to only show
    plugins or/and categories. If r is True, then show recurively
    everthing within the subdirs.

    input:
        cat         category to show content of
        showPlg     boolean to indicate whether to show plugins
        showCat     boolean to indicate whether to show categories
        r           boolean to indicate to scan recursively
        l           boolean to indicate that details are requested too
        force_reload    boolean to trigger reloading of remote content

    ouput:
        content     a list of the categories content

    """
    content = []
    WITH_ID = 5
    WITH_GRPID = 8

    # if we changed something (e.g. updating groups) we want the client to
    # fetch the update even if the user did not explicitly asks for
    try:
        force_reload = listdir.update_happened
    except AttributeError:
        pass

    # request content
    try:
        response = cat.listContent(force_reload)
    except Exception as e:
        print(e)
        if not session.project:
            return []
        else:
            response = []

    # iterate over all categories, respectively plugins. every category has
    # at least an identifier and a name.
    for c in response:
        cid_str = str(c.id)
        spaces = WITH_ID - len(cid_str)
        cid = "{spaces}{id}".format(spaces=" " * spaces,
                                    id=cid_str)

        if isinstance(c, remote.plugin.RemotePlugin) and showPlg:
            if l:
                if c.grpid:
                    spaces = WITH_GRPID - len(c.grpid)
                    grpid = c.grpid
                else:
                    spaces = WITH_GRPID
                    grpid = ""

                grpid = "{spaces}{grpid}".format(spaces=" " * spaces,
                                                 grpid=grpid)

                plg = "{id} {grpid} {name}".format(id=cid,
                                                   grpid=grpid,
                                                   name=c.name)
            else:
                plg = c.name
            content.append(plg)

        elif isinstance(c, RemoteCategory):
            if l:
                plg = "%s %s" % (cid, c.name)
            else:
                plg = c.name
            content.append(plg)

            if r:
                content.extend(listdir(session, c, showPlg, showCat, r, l))

    return content

def listdirToStr(session, r=False, l=False, reload=False):
    """
    returns a printable string of current dirs content

    input
        r       print content of subdirectories
        l       list style
        reload  refresh list

    output:
        return string containing dir's content
    """

    content = ["<id> <connection group id> <name>"] if l else []
    content += listdir(session,
                       cat=session.current_category,
                       r=r,
                       l=l,
                       force_reload=reload)

    print("\n".join(content) if l else " ".join(content))
