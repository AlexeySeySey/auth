package helper

import (
	"strings"
	"regexp"
	minify "github.com/tdewolff/minify/v2"
		"github.com/tdewolff/minify/v2/css"
		"github.com/tdewolff/minify/v2/html"
		"github.com/tdewolff/minify/v2/js"
)

// return page code and page script
func ParsePage(html string) (string, string) {
	m := minify.New()
	m.AddFunc("text/html", html.Minify)
	s, err = m.String("text/html", html)
if err != nil {
	return "", "", err
}
	return fetchPage(s), fetchScriptCode(fetchScript(s)), nil
}

// remove <script>....</script> from page
func fetchPage(html string) string {
    return strings.Replace(html, fetchScript(html), "", -1)
}

func fetchScript(html string) string {
	 r := regexp.MustCompile(`<script>(.+)?<\/script>`)
	 return r.FindStringSubmatch(s)[0]
}

func fetchScriptCode(str string) string {
	out := strings.Replace(str, "<script>", "", -1)
	return strings.Replace(out, "</script>", "", -1)
}