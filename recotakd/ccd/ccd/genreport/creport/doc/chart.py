#!/usr/bin/env python2
# Copyright (C) 2007 Soren Roug, European Environment Agency
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
#
# This is free software.  You may redistribute it under the terms
# of the Apache license and the GNU General Public License Version
# 2 or at your option any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public
# License along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
#
# Contributor(s):
#
 
# This is an example of an OpenDocument Text with an embedded Chart.
#
from odf import chart, style, table, text, draw
from odf.opendocument import OpenDocumentChart, OpenDocumentText
from odf.text import P 

# local modules
from styles import riskCritical, riskHigh, riskMedium, riskLow, riskNone
from datatable import DataTable

class PieChart(object):
 	def __init__(self, chartWidth, chartHeight, chartType):
		self.charttype = 'chart:'+chartType
		self.subtype = 'normal'  # 'percentage', 'stacked' or 'normal'
		self.threedimensional = "false"
		self.x_axis = "Risk"
		self.y_axis = "Amount"
		self.width = chartWidth
		self.height = chartHeight
		self.values = (1,2,3)
		self.title = None
		self.subtitle = None

	def __call__(self, doc):
		chartstyle  = style.Style(name="chartstyle", family="chart")
		chartstyle.addElement( style.GraphicProperties(stroke="none", fillcolor="#ffffff"))
		doc.automaticstyles.addElement(chartstyle)

		mychart = chart.Chart(width=self.width, height=self.height,stylename=chartstyle, attributes={'class':self.charttype})
		doc.chart.addElement(mychart)

		# Title
		if self.title:
			titlestyle = style.Style(name="titlestyle", family="chart")
			titlestyle.addElement( style.GraphicProperties(stroke="none", fill="none"))
			titlestyle.addElement( style.TextProperties(fontfamily="'Nimbus Sans L'",fontfamilygeneric="swiss", fontpitch="variable", fontsize="13pt"))
			doc.automaticstyles.addElement(titlestyle)
			mytitle = chart.Title(x="185pt", y="27pt", stylename=titlestyle)
			mytitle.addElement( text.P(text=self.title))
			mychart.addElement(mytitle)

		# Subtitle
		if self.subtitle:
			subtitlestyle = style.Style(name="subtitlestyle", family="chart")
			subtitlestyle.addElement( style.GraphicProperties(stroke="none", fill="none"))
			subtitlestyle.addElement( style.TextProperties(fontfamily="'Nimbus Sans L'",fontfamilygeneric="swiss", fontpitch="variable", fontsize="10pt"))
			doc.automaticstyles.addElement(subtitlestyle)
			subtitle = chart.Subtitle(x="50pt", y="50pt", stylename=subtitlestyle)
			subtitle.addElement( text.P(text= self.subtitle))	
			mychart.addElement(subtitle)

		# Legend
		legendstyle = style.Style(name="legendstyle", family="chart")
		legendstyle.addElement( style.GraphicProperties(fill="none"))
		legendstyle.addElement( style.TextProperties(fontfamily="'Nimbus Sans L'",fontfamilygeneric="swiss", fontpitch="variable", fontsize="8pt"))
		doc.automaticstyles.addElement(legendstyle)

		mylegend = chart.Legend(legendposition="end", legendalign="center", stylename=legendstyle)
		mychart.addElement(mylegend)

		# Plot area
		plotstyle = style.Style(name="plotstyle", family="chart")
		if self.subtype == "stacked": 
			percentage="false"; stacked="true"
		elif self.subtype == "percentage": 
			percentage="true"; stacked="false"
		else: 
			percentage="false"; stacked="false"
	
		plotstyle.addElement( style.ChartProperties(seriessource="columns",percentage=percentage, stacked=stacked,threedimensional=self.threedimensional))
		doc.automaticstyles.addElement(plotstyle)
 
		plotarea = chart.PlotArea(datasourcehaslabels=self.datasourcehaslabels, stylename=plotstyle)
		mychart.addElement(plotarea)

		# Style for the X,Y axes
		axisstyle = style.Style(name="axisstyle", family="chart")
		axisstyle.addElement( style.ChartProperties(displaylabel="true"))
		axisstyle.addElement( style.TextProperties(fontfamily="'Nimbus Sans L'",
		fontfamilygeneric="swiss", fontpitch="variable", fontsize="8pt"))
		doc.automaticstyles.addElement(axisstyle)

		# Title for the X axis
		xaxis = chart.Axis(dimension="x", name="primary-x", stylename=axisstyle)
		plotarea.addElement(xaxis)
		xt = chart.Title()
		xaxis.addElement(xt)
		xt.addElement(text.P(text=self.x_axis))

		# Title for the Y axis
		yaxis = chart.Axis(dimension="y", name="primary-y", stylename=axisstyle)
		plotarea.addElement(yaxis)
		yt = chart.Title()
		yaxis.addElement(yt)
		yt.addElement(text.P(text=self.y_axis))

		# chart colors
		piestyle = style.Style(name="series", family="chart")
		piestyle.addElement( style.GraphicProperties(fillcolor="#000000"))
		doc.automaticstyles.addElement(piestyle)

		piestyle = style.Style(name="piestyle.critical", family="chart")
		piestyle.addElement( style.ChartProperties(solidtype="cuboid"))
		piestyle.addElement( style.GraphicProperties(fillcolor=riskCritical))
		doc.automaticstyles.addElement(piestyle)

		piestyle = style.Style(name="piestyle.high", family="chart")
		piestyle.addElement( style.ChartProperties(solidtype="cuboid"))
		piestyle.addElement( style.GraphicProperties(fillcolor=riskHigh))
		doc.automaticstyles.addElement(piestyle)

		piestyle = style.Style(name="piestyle.medium", family="chart")
		piestyle.addElement( style.ChartProperties(solidtype="cuboid"))
		piestyle.addElement( style.GraphicProperties(fillcolor=riskMedium))
		doc.automaticstyles.addElement(piestyle)

		piestyle = style.Style(name="piestyle.low", family="chart")
		piestyle.addElement( style.ChartProperties(solidtype="cuboid"))
		piestyle.addElement( style.GraphicProperties(fillcolor=riskLow))
		doc.automaticstyles.addElement(piestyle)

		piestyle = style.Style(name="piestyle.none", family="chart")
		piestyle.addElement( style.ChartProperties(solidtype="cuboid"))
		piestyle.addElement( style.GraphicProperties(fillcolor=riskNone))
		doc.automaticstyles.addElement(piestyle)

		# Set up the data series. OOo doesn't show correctly without them.
		s = chart.Series(valuescellrangeaddress="local-table.$B$2:.$B$6", labelcelladdress="local-table.$B$1",attributes={'class':self.charttype}, stylename="series")
		s.addElement(chart.DataPoint(stylename="piestyle.critical"))
		s.addElement(chart.DataPoint(stylename="piestyle.high"))
		s.addElement(chart.DataPoint(stylename="piestyle.medium"))
		s.addElement(chart.DataPoint(stylename="piestyle.low"))
		s.addElement(chart.DataPoint(stylename="piestyle.none"))
		plotarea.addElement(s)

		# The data are placed in a table inside the chart object - but could also be a
		# table in the main document
		datatable = DataTable(self.values)
		datatable.datasourcehaslabels = self.datasourcehaslabels
		mychart.addElement(datatable())
		 
def drawChart(_document, _values, \
						chartWidth, 
						chartHeight,
						chartType):
	# Create the subdocument
	chartdoc = OpenDocumentChart()
	mychart = PieChart(chartWidth, chartHeight, chartType)

	# These represent the data. Six rows in three columns
	mychart.values = _values
	mychart.datasourcehaslabels = "both"
	mychart(chartdoc)
     
	p = P()
	_document.add(p)
	
	# Create the frame.
	df = draw.Frame(width=chartWidth, height=chartHeight, anchortype="paragraph")
	p.addElement(df)
 
	# Here we add the subdocument to the main document. We get back a reference
	# to use in the href.
	objectloc = _document.addAsObject(chartdoc)
	do = draw.Object(href=objectloc)
	
	# Put the object inside the frame
	df.addElement(do)

