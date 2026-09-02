package handlers

import (
	"log"
	"net/http"
	"strconv"
	"strings"

	"netadmin/internal/auth"
	"netadmin/internal/web"
)

type topoLink struct {
	ID                  int64
	Parent, Child, Port string
	ChildOffline        bool
}

type topoImpact struct {
	Parent     string
	Dependents []string
}

type devOption struct {
	ID   int64
	Name string
}

type topologyPageData struct {
	User    *auth.User
	Active  string
	Links   []topoLink
	Impacts []topoImpact
	Devices []devOption
	Msg     string
}

// TopologyPage — GET /topology : ручные зависимости устройств + влияние при сбое.
func (a *App) TopologyPage(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	data := topologyPageData{User: user, Active: "topology", Msg: r.URL.Query().Get("message")}

	// связи
	rows, err := a.DB.Query(`SELECT t.id, COALESCE(p.hostname,'?'), COALESCE(c.hostname,'?'),
		COALESCE(t.port,''), COALESCE(c.status,'')
		FROM topology_links t
		LEFT JOIN devices p ON p.id=t.parent_device_id
		LEFT JOIN devices c ON c.id=t.child_device_id
		ORDER BY p.hostname, c.hostname`)
	if err == nil {
		for rows.Next() {
			var l topoLink
			var childStatus string
			if rows.Scan(&l.ID, &l.Parent, &l.Child, &l.Port, &childStatus) == nil {
				l.ChildOffline = childStatus == "offline"
				data.Links = append(data.Links, l)
			}
		}
		if err := rows.Err(); err != nil {
			log.Printf("TopologyPage: %v", err)
		}
		rows.Close()
	}

	// влияние: для каждого ОФФЛАЙН родителя — список зависимых детей
	irows, err := a.DB.Query(`SELECT p.hostname, c.hostname
		FROM topology_links t
		JOIN devices p ON p.id=t.parent_device_id
		JOIN devices c ON c.id=t.child_device_id
		WHERE p.status='offline' ORDER BY p.hostname`)
	if err == nil {
		impMap := map[string][]string{}
		var order []string
		for irows.Next() {
			var parent, child string
			if irows.Scan(&parent, &child) == nil {
				if _, ok := impMap[parent]; !ok {
					order = append(order, parent)
				}
				impMap[parent] = append(impMap[parent], child)
			}
		}
		if err := irows.Err(); err != nil {
			log.Printf("TopologyPage: %v", err)
		}
		irows.Close()
		for _, p := range order {
			data.Impacts = append(data.Impacts, topoImpact{Parent: p, Dependents: impMap[p]})
		}
	}

	// устройства для формы
	drows, err := a.DB.Query("SELECT id, hostname FROM devices ORDER BY hostname")
	if err == nil {
		for drows.Next() {
			var o devOption
			if drows.Scan(&o.ID, &o.Name) == nil {
				data.Devices = append(data.Devices, o)
			}
		}
		if err := drows.Err(); err != nil {
			log.Printf("TopologyPage: %v", err)
		}
		drows.Close()
	}

	web.RenderPage(w, "topology", data)
}

// AddTopologyLink — POST /topology/add (admin) : родитель → ребёнок (зависимость).
func (a *App) AddTopologyLink(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil || !user.IsAdmin() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	_ = r.ParseForm()
	parent, _ := strconv.ParseInt(r.FormValue("parent_device_id"), 10, 64)
	child, _ := strconv.ParseInt(r.FormValue("child_device_id"), 10, 64)
	if parent == 0 || child == 0 || parent == child {
		http.Redirect(w, r, "/topology?message=Выберите+два+разных+устройства", http.StatusSeeOther)
		return
	}
	a.DB.Exec("INSERT INTO topology_links (parent_device_id, child_device_id, link_type, port) VALUES (?,?,'manual',?)",
		parent, child, strings.TrimSpace(r.FormValue("port")))
	auth.LogAction(a.DB, user.ID, "topology_add", strconv.FormatInt(parent, 10), strconv.FormatInt(child, 10))
	http.Redirect(w, r, "/topology?message=Связь+добавлена", http.StatusSeeOther)
}

// DeleteTopologyLink — POST /topology/{id}/delete (admin).
func (a *App) DeleteTopologyLink(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil || !user.IsAdmin() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	a.DB.Exec("DELETE FROM topology_links WHERE id=?", id)
	http.Redirect(w, r, "/topology?message=Связь+удалена", http.StatusSeeOther)
}
