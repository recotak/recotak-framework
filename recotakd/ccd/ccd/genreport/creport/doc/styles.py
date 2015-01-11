# coding: utf8
from strings import get_string
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
from odf.style import *
from odf.text import *
from odf.draw import *

# own modules
from curesecStrings import *

# colours
curesecOrange = "#ff9e00"
riskCritical = "#af39dd"
riskHigh = "#cf1f21"
riskMedium = "#ffd200"
riskLow = "#17c870"
riskNone = "#ffffff"

curesecFont = "'Iskoola Pota'"
picture = "/usr/img/header_logo.tif"
outlinelevel = 5

class DocumentStyle:
    def __init__(self):

        self._mp = None # master page
        self._pl = None # page layout

        self._language = "DE"

        # user fields
        self._ufProjekt = "Projekt"
        self._ufVersion = "Version"
        self._ufDatum = "Datum"
        self._ufClientName = "Kundenname"
        self._ufClientAddress = "Kundenadresse"
        self._ufDatumStart = "Beginn"
        self._ufDatumEnd = "Ende"
        #self._ufAuthor = "Autor"
        self._ufAuthorAddress = "Adresse"

    def defineCuresecStyles(self, _document, _language):
        self._language = _language

        _border = "0.03pt solid " + curesecOrange
        _padding = "4pt"

        # allow page breaks
        _document.text.setAttribute('usesoftpagebreaks','true')

        widthshort = Style(name="wCol0", family="table-column")
        widthshort.addElement(TableColumnProperties(columnwidth='0.7729in'))
        _document.automaticstyles.addElement(widthshort)
        column_prop = TableColumnProperties(useoptimalcolumnwidth="true")
        widthshort.addElement(column_prop)

        widthshort = Style(name="wCol0.big", family="table-column")
        widthshort.addElement(TableColumnProperties(columnwidth='6cm'))
        _document.automaticstyles.addElement(widthshort)
        column_prop = TableColumnProperties(useoptimalcolumnwidth="true")
        widthshort.addElement(column_prop)

        widthshort = Style(name="wCol1", family="table-column")
        widthshort.addElement(TableColumnProperties(columnwidth='1.5035in'))
        _document.automaticstyles.addElement(widthshort)
        column_prop = TableColumnProperties(useoptimalcolumnwidth="true")
        widthshort.addElement(column_prop)

        widthshort = Style(name="wCol2", family="table-column")
        widthshort.addElement(TableColumnProperties(columnwidth='4.4188in'))
        _document.automaticstyles.addElement(widthshort)
        column_prop = TableColumnProperties(useoptimalcolumnwidth="true")
        widthshort.addElement(column_prop)

        widthshort = Style(name="wCol2.small", family="table-column")
        widthshort.addElement(TableColumnProperties(columnwidth='2cm'))
        _document.automaticstyles.addElement(widthshort)


        textstyle = Style(name="default", family="paragraph")
        text = TextProperties(fontsize="11pt", fontfamily=curesecFont)
        textstyle.addElement(text)
        para = ParagraphProperties(marginbottom="0.200in")
        textstyle.addElement(para)
        _document.automaticstyles.addElement(textstyle)

        # create style for heading
        backgroundOrange = Style(name="bgrOrange", family="table-cell")
        color = TableCellProperties(backgroundcolor=curesecOrange, border=_border, padding=_padding)
        backgroundOrange.addElement(color)
        text = TextProperties(color="#ffffff", fontsize="12pt",fontfamily=curesecFont)
        backgroundOrange.addElement(text)
        paragraph = ParagraphProperties(textalign="center")
        backgroundOrange.addElement(paragraph)
        _document.automaticstyles.addElement(backgroundOrange)

        # border col0
        col_left = Style(name="col_left", family="table-cell")
        col_left_border = TableCellProperties(border=_border, padding=_padding,
                                    borderleft=_border,
                                    borderbottom=_border,
                                    bordertop="none",
                                    borderright="none"
                                    )
        col_left.addElement(col_left_border)
        paragraph = ParagraphProperties(textalign="center")
        col_left.addElement(paragraph)
#        column_prop = TableColumnProperties(useoptimalcolumnwidth=True)
#        col_left.addElement(column_prop)
        _document.automaticstyles.addElement(col_left)

        # border middle
        col_middle = Style(name="col_middle", family="table-cell")
        color = TableCellProperties(padding=_padding,
                                    borderleft=_border,
                                    borderbottom=_border,
                                    bordertop="none",
                                    borderright="none"
                                    )
        paragraph = ParagraphProperties(textalign="center")
        col_middle.addElement(paragraph)
        col_middle.addElement(color)
#        column_prop = TableColumnProperties(useoptimalcolumnwidth=True)
#        col_middle.addElement(column_prop)
        _document.automaticstyles.addElement(col_middle)


        # border col2 white
        border = Style(name="borderCol2.", family="table-cell")
        color = TableCellProperties(padding=_padding,
                                    borderleft=_border,
                                    borderbottom=_border,
                                    bordertop="none",
                                    borderright=_border)
        border.addElement(color)
        paragraph = ParagraphProperties(textalign="center")
        border.addElement(paragraph)
        _document.automaticstyles.addElement(border)

        # border col2 critical
        border = Style(name="col_risko_critical", family="table-cell")
        color = TableCellProperties(backgroundcolor=riskCritical,
                                    padding=_padding,
                                    borderleft=_border,
                                    borderbottom=_border,
                                    bordertop="none",
                                    borderright=_border)
        border.addElement(color)
        text = TextProperties(color="#ffffff", fontsize="12pt",fontfamily=curesecFont)
        border.addElement(text)
        paragraph = ParagraphProperties(textalign="center")
        border.addElement(paragraph)
        _document.automaticstyles.addElement(border)

        # border col2 high
        border = Style(name="col_risiko_high", family="table-cell")
        color = TableCellProperties(backgroundcolor=riskHigh,
                                    padding=_padding,
                                    borderleft=_border,
                                    borderbottom=_border,
                                    bordertop="none",
                                    borderright=_border)
        border.addElement(color)
        text = TextProperties(color="#ffffff", fontsize="12pt",fontfamily=curesecFont)
        border.addElement(text)
        paragraph = ParagraphProperties(textalign="center")
        border.addElement(paragraph)
        _document.automaticstyles.addElement(border)

        # border col2 medium
        border = Style(name="col_risiko_medium", family="table-cell")
        color = TableCellProperties(backgroundcolor=riskMedium,
                                    padding=_padding,
                                    borderleft=_border,
                                    borderbottom=_border,
                                    bordertop="none",
                                    borderright=_border)
        border.addElement(color)
        text = TextProperties(color="#ffffff", fontsize="12pt",fontfamily=curesecFont)
        border.addElement(text)
        paragraph = ParagraphProperties(textalign="center")
        border.addElement(paragraph)
        _document.automaticstyles.addElement(border)

        # border col2 low
        border = Style(name="col_risiko_low", family="table-cell")
        color = TableCellProperties(backgroundcolor=riskLow,
                                    padding=_padding,
                                    borderleft=_border,
                                    borderbottom=_border,
                                    bordertop="none",
                                    borderright=_border)
        border.addElement(color)
        text = TextProperties(color="#ffffff", fontsize="12pt",fontfamily=curesecFont)
        border.addElement(text)
        paragraph = ParagraphProperties(textalign="center")
        border.addElement(paragraph)
        _document.automaticstyles.addElement(border)

        # border col2 none
        border = Style(name="borderCol2.None", family="table-cell")
        color = TableCellProperties(padding=_padding,
                                    borderleft=_border,
                                    borderbottom=_border,
                                    bordertop="none",
                                    borderright=_border)
        border.addElement(color)
        paragraph = ParagraphProperties(textalign="center")
        border.addElement(paragraph)
        _document.automaticstyles.addElement(border)

        # border col2
        col_right = Style(name="col_right", family="table-cell")
        color = TableCellProperties(padding=_padding,
                                    borderleft=_border,
                                    borderbottom=_border,
                                    bordertop="none",
                                    borderright=_border)
        col_right.addElement(color)
        paragraph = ParagraphProperties(textalign="center")
        col_right.addElement(paragraph)
#        column_prop = TableColumnProperties(useoptimalcolumnwidth="true")
#        col_right.addElement(column_prop)
        _document.automaticstyles.addElement(col_right)

        # border col2 centered text
        border = Style(name="borderCol2.center", family="table-cell")
        color = TableCellProperties(padding=_padding,
                                    borderleft=_border,
                                    borderbottom=_border,
                                    bordertop="none",
                                    borderright=_border)
        border.addElement(color)
        paragraph = ParagraphProperties(textalign="center")
        border.addElement(paragraph)
        _document.automaticstyles.addElement(border)

        # col2 critical without border
        border = Style(name="col2.Critical", family="table-cell")
        color = TableCellProperties(backgroundcolor=riskCritical, padding=_padding)
        border.addElement(color)
        text = TextProperties(color="#ffffff", fontsize="12pt",fontfamily=curesecFont)
        border.addElement(text)
        paragraph = ParagraphProperties(textalign="center")
        border.addElement(paragraph)
        _document.automaticstyles.addElement(border)

        # col2 annotation
        border = Style(name="col2.anno", family="table-cell")
        color = TableCellProperties(padding=_padding)
        border.addElement(color)
        text = TextProperties(fontsize="12pt")
        border.addElement(text)
        _document.automaticstyles.addElement(border)

        # col2 high without border
        border = Style(name="col2.High", family="table-cell")
        color = TableCellProperties(backgroundcolor=riskHigh, padding=_padding)
        border.addElement(color)
        text = TextProperties(color="#ffffff", fontsize="12pt",fontfamily=curesecFont)
        border.addElement(text)
        paragraph = ParagraphProperties(textalign="center")
        border.addElement(paragraph)
        _document.automaticstyles.addElement(border)

        # col2 medium without border
        border = Style(name="col2.Medium", family="table-cell")
        color = TableCellProperties(backgroundcolor=riskMedium, padding=_padding)
        border.addElement(color)
        text = TextProperties(color="#ffffff", fontsize="12pt",fontfamily=curesecFont)
        border.addElement(text)
        paragraph = ParagraphProperties(textalign="center")
        border.addElement(paragraph)
        _document.automaticstyles.addElement(border)

        # col2 low without border
        border = Style(name="col2.Low", family="table-cell")
        color = TableCellProperties(backgroundcolor=riskLow, padding=_padding)
        border.addElement(color)
        text = TextProperties(color="#ffffff", fontsize="12pt",fontfamily=curesecFont)
        border.addElement(text)
        paragraph = ParagraphProperties(textalign="center")
        border.addElement(paragraph)
        _document.automaticstyles.addElement(border)

        # col2 none without border
        border = Style(name="col2.None", family="table-cell")
        color = TableCellProperties(padding=_padding)
        border.addElement(color)
        paragraph = ParagraphProperties(textalign="center")
        border.addElement(paragraph)
        _document.automaticstyles.addElement(border)

        # H1
        header = Style(name="header.1", family="paragraph")
        text = TextProperties(color=curesecOrange, fontsize="14pt",fontfamily=curesecFont)
        header.addElement(text)
        paragraph = ParagraphProperties(margintop="2cm", marginbottom="0.5cm")
        header.addElement(paragraph)
        _document.automaticstyles.addElement(header)

        # H2
        header = Style(name="header.2", family="paragraph")
        text = TextProperties(color=curesecOrange, fontsize="12pt",fontfamily=curesecFont)
        header.addElement(text)
        paragraph = ParagraphProperties(margintop="2cm", marginbottom="0.5cm")
        header.addElement(paragraph)
        _document.automaticstyles.addElement(header)

        # H3
        header = Style(name="header.3", family="paragraph")
        text = TextProperties(color=curesecOrange, fontsize="12pt",fontfamily=curesecFont)
        header.addElement(text)
        paragraph = ParagraphProperties(margintop="2cm", marginbottom="0.5cm")
        header.addElement(paragraph)
        _document.automaticstyles.addElement(header)

        # H5
        header = Style(name="header.5", family="paragraph")
        text = TextProperties(color=curesecOrange, fontsize="12pt", fontstyle="italic",)
        header.addElement(text)
        paragraph = ParagraphProperties(margintop="0.3cm", marginbottom="0.1cm")
        header.addElement(paragraph)
        _document.automaticstyles.addElement(header)

        # ip: column left - usually a bit larger than the right one
        widthshort = Style(name="Wshort", family="table-column")
        widthshort.addElement(TableColumnProperties(columnwidth="10cm"))
        _document.automaticstyles.addElement(widthshort)
        widthwide = Style(name="Wwide", family="table-column")
        widthwide.addElement(TableColumnProperties(columnwidth="3cm"))
        _document.automaticstyles.addElement(widthwide)

        # lists, numbered
        numberedList = ListStyle(name="numberedList")
        numstyle1 = ListLevelStyleNumber(level="1", stylename="Numbering_20_Symbols", numsuffix=".", numformat='1')
        L5prop1 = ListLevelProperties( minlabelwidth="0.25in")
        numstyle1.addElement(L5prop1)
        numberedList.addElement(numstyle1)
        _document.automaticstyles.addElement(numberedList)

        # annotation table
        widthshort = Style(name="annotationLeft", family="table-column")
        widthshort.addElement(TableColumnProperties(columnwidth="1cm"))
        _document.automaticstyles.addElement(widthshort)

        widthshort = Style(name="annotationRight", family="table-column")
        widthshort.addElement(TableColumnProperties(columnwidth="7cm"))
        _document.automaticstyles.addElement(widthshort)

        # master page
        self._pl = PageLayout(name="Mpm1")
        pageLayout = PageLayoutProperties(pagewidth="21.001cm", pageheight="29.7cm", printorientation="portrait", margintop="2cm", marginbottom="2cm", marginleft="2cm", marginright="1.893cm")
        self._pl.addElement(pageLayout)
        _document.automaticstyles.addElement(self._pl)
        self._mp = MasterPage(name="Standard", pagelayoutname=self._pl)
        _document.masterstyles.addElement(self._mp)

        # pagebreak
        pagebreak = Style(name="pagebreak", family="paragraph")
        _document.automaticstyles.addElement(pagebreak)
        paragraph = ParagraphProperties(breakafter="page")
        pagebreak.addElement(paragraph)

    def setFooterData(self, _document):
        # footer
        fs = FooterStyle()
        headerFooterProp = HeaderFooterProperties(minheight="0cm", marginleft="0cm", marginright="0cm", margintop="0.499cm")
        fs.addElement(headerFooterProp)
        self._pl.addElement(fs)
        f = Footer()
        self._mp.addElement(f)

        # styles in 'footer'
        sf = Style(name="Footer", family="paragraph", attributes={'class':"extra"})
        text = TextProperties(color=curesecOrange, fontfamily=curesecFont, fontsize="9pt")
        sf.addElement(text)
        _document.styles.addElement(sf)

        # copyright
        pCopyright = P(stylename=sf, text=get_string(12, self._language))
        f.addElement(pCopyright)

        # page number/count styles
        ps = Style(name="MP5", family="paragraph", parentstylename=sf)
        _document.styles.addElement(ps)
        pageStyle = ParagraphProperties(textalign="right")
        ps.addElement(pageStyle)

        pPage = P(stylename=ps)
        f.addElement(pPage)

        # linebreak
        lb = LineBreak()
        pPage.addElement(lb)

        # 'Seite'
        wordingPage = Span(text=get_string(8, self._language) + " ")
        pPage.addElement(wordingPage)

        # current page
        currentPage = PageNumber(selectpage="current")
        pPage.addElement(currentPage)

        # slash
        slash = Span(text="/")
        pPage.addElement(slash)

        # page count
        pageCount = PageCount()
        pPage.addElement(pageCount)


    def setHeaderData(self, _document, projekt, datum, version):
        # header
        hs = HeaderStyle()
        headerFooterProp = HeaderFooterProperties(minheight="0cm",
                                                  marginleft="0cm",
                                                  marginright="0cm",
                                                  marginbottom="0.499cm")
        hs.addElement(headerFooterProp)
        self._pl.addElement(hs)

        h = Header()
        self._mp.addElement(h)

        # styles in 'header'
        sh = Style(name="Header",
                   family="paragraph",
                   attributes={'class':"extra"})
        text = TextProperties(color=curesecOrange,
                              fontfamily=curesecFont,
                              fontsize="9pt")
        sh.addElement(text)
        _document.styles.addElement(sh)

        # add user fields
        userfieldDecls = UserFieldDecls()
        h.addElement(userfieldDecls)
        userfieldProjekt = UserFieldDecl(valuetype="string",
                                         stringvalue=projekt,
                                         name=self._ufProjekt)
        userfieldDecls.addElement(userfieldProjekt)

        userfieldDatum = UserFieldDecl(valuetype="string",
                                       stringvalue=datum,
                                       name=self._ufDatum)
        userfieldDecls.addElement(userfieldDatum)

        userfieldVersion = UserFieldDecl(valuetype="string",
                                         stringvalue=version,
                                         name=self._ufVersion)
        userfieldDecls.addElement(userfieldVersion)

        # Paragaph settings in header
        mp1 = Style(name="MP1", family="paragraph", parentstylename=sh)
        paragraph = ParagraphProperties(marginleft="0cm",
                                        marginright="0cm",
                                        lineheight="100%",
                                        textalign="start",
                                        justifysingleword="false",
                                        textindent="0cm",
                                        autotextindent="false",
                                        pagenumber="auto",
                                        backgroundcolor="transparent",
                                        shadow="none",
                                        numberlines="false",
                                        linenumber="0")

        bi = BackgroundImage()
        paragraph.addElement(bi)
        mp1.addElement(paragraph)

        text = TextProperties(color=curesecOrange,
                              fontfamily=curesecFont,
                              fontsize="9pt")
        mp1.addElement(text)
        _document.automaticstyles.addElement(mp1)

        # header: projekt
        _sep = ": "
        pProjekt = P(stylename=mp1)
        h.addElement(pProjekt)
        sProjekt = Span(text=get_string(11, self._language) + _sep)
        pProjekt.addElement(sProjekt)
        sUserfieldProjekt = Span()
        pProjekt.addElement(sUserfieldProjekt)
        getUserfieldProjekt = UserFieldGet(name=self._ufProjekt)
        sUserfieldProjekt.addElement(getUserfieldProjekt)

        # header: datum
        pDatum = P(stylename=mp1)
        h.addElement(pDatum)
        sDatum = Span(text=get_string(10, self._language) + _sep)
        pDatum.addElement(sDatum)
        sUserfieldDatum = Span()
        pDatum.addElement(sUserfieldDatum)
        getUserfieldDatum = UserFieldGet(name=self._ufDatum)
        sUserfieldDatum.addElement(getUserfieldDatum)

        # header: version
        pVersion = P(stylename=mp1)
        h.addElement(pVersion)
        sVersion = Span(text=get_string(9, self._language) + _sep)
        pVersion.addElement(sVersion)
        sUserfieldVersion = Span()
        pVersion.addElement(sUserfieldVersion)
        getUserfieldVersion = UserFieldGet(name=self._ufVersion)
        sUserfieldVersion.addElement(getUserfieldVersion)

        # empty 1
        pEmpty = P(stylename="MP4")
        h.addElement(pEmpty)

        # empty 2
        pEmpty = P(stylename="MP4")
        h.addElement(pEmpty)

        # curesec logo style in header
        ps = Style(name="Mfr1", family="graphic")
        _document.styles.addElement(ps)
        graphic = GraphicProperties(horizontalpos="right",
                                    horizontalrel="paragraph",
                                    mirror="none",
                                    clip="rect(0cm, 0cm, 0cm, 0cm)",
                                    luminance="0%",
                                    contrast="0%",
                                    red="0%",
                                    green="0%",
                                    blue="0%",
                                    gamma="100%",
                                    colorinversion="false",
                                    imageopacity="100%",
                                    colormode="standard")
        ps.addElement(graphic)

        # curesc logo in header
        photoframe = Frame(stylename=ps,
                           width="4.902cm",
                           height="1.457cm",
                           x="12.167cm",
                           y="0.058cm",
                           anchortype="paragraph")
        pProjekt.addElement(photoframe)
        href = _document.addPicture(picture)
        photoframe.addElement(Image(href=href,
                                    type="simple",
                                    show="embed",
                                    actuate="onLoad"))

    def addUserfieldsToBody(self, _document, projekt, date, dateStart, dateEnd,
                            author, authorAddress, clientName, clientAddress,
                                                                      version):
        userfieldDecls = UserFieldDecls()
        _document.text.addElement(userfieldDecls)

        userfieldProjekt = UserFieldDecl(valuetype="string",
                                         stringvalue=projekt,
                                         name=self._ufProjekt)
        userfieldDecls.addElement(userfieldProjekt)

        userfieldDatum = UserFieldDecl(valuetype="string",
                                       stringvalue=date,
                                       name=self._ufDatum)
        userfieldDecls.addElement(userfieldDatum)

        userfieldVersion = UserFieldDecl(valuetype="string",
                                         stringvalue=version,
                                         name=self._ufVersion)
        userfieldDecls.addElement(userfieldVersion)

        userfieldClientName = UserFieldDecl(valuetype="string",
                                            stringvalue=clientName,
                                            name=self._ufClientName)
        userfieldDecls.addElement(userfieldClientName)

        userfieldClientAddress = UserFieldDecl(valuetype="string",
                                               stringvalue=clientAddress,
                                               name=self._ufClientAddress)
        userfieldDecls.addElement(userfieldClientAddress)

    #   userfieldAuthor = UserFieldDecl(valuetype="string",
    #                                   stringvalue=str(author),
    #                                   name=self._ufAuthor)
    #   userfieldDecls.addElement(userfieldAuthor)

        userfieldAuthorAddress = UserFieldDecl(valuetype="string",
                                               stringvalue=authorAddress,
                                               name=self._ufAuthorAddress)
        userfieldDecls.addElement(userfieldAuthorAddress)

        userfieldStart = UserFieldDecl(valuetype="string",
                                       stringvalue=dateStart,
                                       name=self._ufDatumStart)
        userfieldDecls.addElement(userfieldStart)

        userfieldEnd = UserFieldDecl(valuetype="string",
                                     stringvalue=dateEnd,
                                     name=self._ufDatumEnd)
        userfieldDecls.addElement(userfieldEnd)


    def addLines(self, _document, amount):
        for i in range(amount):
            p = P()
            _document.text.addElement(p)

    def addTitle(self, _document):
        # title of document
        pTitle = P(stylename='deckblatt.title',
                   text=get_string(15, self._language))
        _document.text.addElement(pTitle)

        # projectName
        pProjekt = P(stylename='deckblatt.projekt')
        _document.text.addElement(pProjekt)
        getUfProjekt = UserFieldGet(name=self._ufProjekt)
        pProjekt.addElement(getUfProjekt)

        # version
        pVersion = P(stylename='deckblatt.projekt')
        _document.text.addElement(pVersion)
        sVersion = Span(text=get_string(9, self._language) + ": ")
        pVersion.addElement(sVersion)
        getUfVersion = UserFieldGet(name=self._ufVersion)
        pVersion.addElement(getUfVersion)

        # empty line
        self.addLines(_document, 1)

        # clientName
        pClient = P(stylename='deckblatt.title')
        _document.text.addElement(pClient)
        getUfClientName = UserFieldGet(name=self._ufClientName)
        pClient.addElement(getUfClientName)

        # zeitraum
        pRange = P(stylename='deckblatt.projekt')
        _document.text.addElement(pRange)
        getUfStart = UserFieldGet(name=self._ufDatumStart)
        pRange.addElement(getUfStart)
        sSeperator = Span(text="-")
        pRange.addElement(sSeperator)
        getUfEnd = UserFieldGet(name=self._ufDatumEnd)
        pRange.addElement(getUfEnd)

        # datum
        pDatum = P(stylename='deckblatt.projekt')
        _document.text.addElement(pDatum)
        sDatum = Span(text=get_string(10, self._language)+ ": ")
        pDatum.addElement(sDatum)
        getUfDatum = UserFieldGet(name=self._ufDatum)
        pDatum.addElement(getUfDatum)

    def defineDeckblattStyles(self, _document):
        # title
        title = Style(name="deckblatt.title", family="paragraph", parentstylename="default")
        _document.automaticstyles.addElement(title)
        text = TextProperties(fontsize="28pt", fontfamily=curesecFont, color=curesecOrange)
        title.addElement(text)
        paragraph = ParagraphProperties(textalign="center")
        title.addElement(paragraph)

        # projekt
        projekt = Style(name="deckblatt.projekt", family="paragraph", parentstylename="default")
        _document.automaticstyles.addElement(projekt)
        text = TextProperties(fontsize="14pt", fontfamily=curesecFont, color=curesecOrange)
        projekt.addElement(text)
        paragraph = ParagraphProperties(textalign="center")
        projekt.addElement(paragraph)

        # version
        # same styles as 'projekt'

        # title
        # same styles as 'title'

        # zeitraum
        # same as 'projekt'

        # datum
        # same as 'projekt'

        # declaration
        _decColor = '#4c4c4c'
        deklaration = Style(name="deckblatt.deklaration", family="paragraph", parentstylename="default")
        _document.automaticstyles.addElement(deklaration)
        text = TextProperties(fontsize="14pt", fontfamily=curesecFont, color=_decColor)
        deklaration.addElement(text)
        paragraph = ParagraphProperties(textalign="center", marginbottom="10pt")
        deklaration.addElement(paragraph)

        deklarationKlein = Style(name="deckblatt.deklaration.klein", family="paragraph", parentstylename="default")
        _document.automaticstyles.addElement(deklarationKlein)
        text = TextProperties(fontsize="11pt", fontfamily=curesecFont, color=_decColor)
        deklarationKlein.addElement(text)
        paragraph = ParagraphProperties(textalign="center", marginleft="50pt", marginright="50pt")
        deklarationKlein.addElement(paragraph)


    def addDeclaration(self, _document):
        # title 'Confidential'
        pDeclarationTitle = P(stylename='deckblatt.deklaration',
                              text=get_string(6, self._language))
        _document.text.addElement(pDeclarationTitle)

        # declaration
        pDeclaration = P(stylename='deckblatt.deklaration.klein',
                         text=get_string(5, self._language))
        _document.text.addElement(pDeclaration)


    def addDeckblatt(self, _document,):
        _emptyLines = 10

        # add styles for Deckblatt
        self.defineDeckblattStyles(_document)

        # add some empty lines
        self.addLines(_document, _emptyLines)

        # add Title
        self.addTitle(_document)

        # add declaration
        self.addLines(_document, 3)
        self.addDeclaration(_document)

        # final page break
        self.addPagebreak(_document)

    def addAuftragsgeber(self, _document):
        _level = 1

        # header
        header = H(outlinelevel=_level,
                   stylename='header.1',
                   text=get_string(7, self._language))
        _document.text.addElement(header)

        # clientAddress
        pGeber = P(stylename="vertragspartner.kunde")
        _document.text.addElement(pGeber)
        getUfGeber = UserFieldGet(name=self._ufClientAddress)
        pGeber.addElement(getUfGeber)

    def addAuftragsnehmer(self, _document):
        _level = 1

        # header
        header = H(outlinelevel=_level,
                   stylename='header.1',
                   text=get_string(13, self._language))
        _document.text.addElement(header)

        # clientAddress
        pNehmer = P(stylename="vertragspartner.kunde")
        _document.text.addElement(pNehmer)
        getUfNehmer = UserFieldGet(name=self._ufAuthorAddress)
        pNehmer.addElement(getUfNehmer)


    def defineVertragspartnerStyles(self, _document):
        # header
        projekt = Style(name="vertragspartner.header",
                        family="paragraph",
                        parentstylename="default")
        _document.automaticstyles.addElement(projekt)
        text = TextProperties(fontsize="14pt",
                              fontfamily=curesecFont,
                              color=curesecOrange)
        projekt.addElement(text)

        # auftragsgeber
        projekt = Style(name="vertragspartner.kunde",
                        family="paragraph",
                        parentstylename="default")
        _document.automaticstyles.addElement(projekt)
        text = TextProperties(fontsize="11pt",
                              fontfamily=curesecFont)
        projekt.addElement(text)

        # auftragsnehmer
        # same as auftragsgeber

    def addPagebreak(self, _document):
        pBreak = P(stylename='pagebreak')
        _document.text.addElement(pBreak)

    def addVertragspartner(self, _document):

        # define styles for vertragspartner
        self.defineVertragspartnerStyles(_document)

        # add Auftragsgeber
        self.addAuftragsgeber(_document)

        # add Auftragsnehmer
        self.addAuftragsnehmer(_document)

        # add page break
        self.addPagebreak(_document)

    def addTableOfContent(self, _document):

        # create table of content main node
        tableOfContent = TableOfContent(protected="true",
                                        name=get_string(14, self._language))
        _document.text.addElement(tableOfContent)

        # source of table of content
        tocSource = TableOfContentSource(outlinelevel=str(outlinelevel))
        tableOfContent.addElement(tocSource)

        # index table template
        indexTemplate = IndexTitleTemplate()
        tocSource.addElement(indexTemplate)

        # content entries for table of content
        # entries have to following layout:
        # <number><chapter title> .... <page>
        for i in range(outlinelevel):
            entry = TableOfContentEntryTemplate(outlinelevel=str(i+1), stylename="Entry"+str(i+1))
            tocSource.addElement(entry)

            chapter = IndexEntryChapter()
            entry.addElement(chapter)

            linkStart = IndexEntryLinkStart()
            entry.addElement(linkStart)

            text = IndexEntryText()
            entry.addElement(text)

            linkEnd = IndexEntryLinkEnd()
            entry.addElement(linkEnd)

            dots = IndexEntryTabStop(type="right", leaderchar=".")
            entry.addElement(dots)

            pageNumber = IndexEntryPageNumber()
            entry.addElement(pageNumber)

        # add index body
        indexBody = IndexBody()
        tableOfContent.addElement(indexBody)

        # add page break
        self.addPagebreak(_document)

