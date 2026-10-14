package handlers

import (
	"database/sql"
	"errors"
	"net/http"
	"netadmin/internal/auth"
	"netadmin/internal/deviceaccess"
	"netadmin/internal/web"
	"strconv"
	"strings"
)

type groupChoice struct {
	deviceaccess.Group
	Checked bool
}
type groupDeviceChoice struct {
	deviceRow
	Checked bool
}
type groupsData struct {
	User                  *auth.User
	Active, CSRF, Message string
	Groups                []deviceaccess.Group
	Group                 deviceaccess.Group
	Devices               []groupDeviceChoice
	Editing               bool
}
type userAccessData struct {
	User, Target          *auth.User
	Active, CSRF, Message string
	Scope                 deviceaccess.Scope
	Groups                []groupChoice
}

func (a *App) accessAdmin(w http.ResponseWriter, r *http.Request) (*auth.User, bool) {
	user := auth.CurrentUser(a.DB, r)
	if !user.IsAdmin() {
		http.Error(w, "forbidden", 403)
		return nil, false
	}
	w.Header().Set("Cache-Control", "no-store")
	return user, true
}
func accessError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, deviceaccess.ErrConflict):
		http.Error(w, "Настройки изменились. Обновите страницу и повторите действие.", 409)
	case errors.Is(err, deviceaccess.ErrInvalid):
		http.Error(w, "Проверьте имя, выбранные устройства и группы.", 400)
	case errors.Is(err, sql.ErrNoRows):
		http.Error(w, "Объект не найден", 404)
	case strings.Contains(err.Error(), "UNIQUE constraint"):
		http.Error(w, "Группа с таким именем уже существует.", 409)
	default:
		http.Error(w, "Изменения не сохранены. Повторите позже.", 503)
	}
}
func pathID(r *http.Request) (int64, error) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		return 0, deviceaccess.ErrInvalid
	}
	return id, nil
}

func (a *App) DeviceGroupsPage(w http.ResponseWriter, r *http.Request) {
	user, ok := a.accessAdmin(w, r)
	if !ok {
		return
	}
	groups, err := deviceaccess.Groups(r.Context(), a.DB)
	if err != nil {
		accessError(w, err)
		return
	}
	web.RenderPage(w, "device_groups", groupsData{User: user, Active: "device_groups", CSRF: csrfToken(r), Groups: groups, Message: r.URL.Query().Get("result")})
}
func (a *App) CreateDeviceGroup(w http.ResponseWriter, r *http.Request) {
	user, ok := a.accessAdmin(w, r)
	if !ok {
		return
	}
	id, err := deviceaccess.CreateGroup(r.Context(), a.DB, r.FormValue("name"), r.FormValue("description"), user.ID)
	if err != nil {
		accessError(w, err)
		return
	}
	http.Redirect(w, r, "/device-groups/"+strconv.FormatInt(id, 10)+"?result=created", 303)
}
func (a *App) DeviceGroupPage(w http.ResponseWriter, r *http.Request) {
	user, ok := a.accessAdmin(w, r)
	if !ok {
		return
	}
	id, err := pathID(r)
	if err != nil {
		accessError(w, err)
		return
	}
	group, members, err := deviceaccess.GroupByID(r.Context(), a.DB, id)
	if err != nil {
		accessError(w, err)
		return
	}
	checked := map[int64]bool{}
	for _, id := range members {
		checked[id] = true
	}
	data := groupsData{User: user, Active: "device_groups", CSRF: csrfToken(r), Group: group, Editing: true, Message: r.URL.Query().Get("result")}
	for _, device := range a.listDevices() {
		data.Devices = append(data.Devices, groupDeviceChoice{deviceRow: device, Checked: checked[device.ID]})
	}
	web.RenderPage(w, "device_groups", data)
}
func (a *App) UpdateDeviceGroup(w http.ResponseWriter, r *http.Request) {
	user, ok := a.accessAdmin(w, r)
	if !ok {
		return
	}
	id, err := pathID(r)
	if err != nil {
		accessError(w, err)
		return
	}
	if err = r.ParseForm(); err != nil {
		accessError(w, deviceaccess.ErrInvalid)
		return
	}
	revision, err := strconv.ParseInt(r.FormValue("revision"), 10, 64)
	if err != nil {
		accessError(w, deviceaccess.ErrInvalid)
		return
	}
	members, err := deviceaccess.IDs(r.Form["device"], 5000)
	if err != nil {
		accessError(w, err)
		return
	}
	err = deviceaccess.UpdateGroup(r.Context(), a.DB, deviceaccess.Group{ID: id, Revision: revision, Name: r.FormValue("name"), Description: r.FormValue("description")}, members, user.ID)
	if err != nil {
		accessError(w, err)
		return
	}
	http.Redirect(w, r, "/device-groups/"+strconv.FormatInt(id, 10)+"?result=saved", 303)
}
func (a *App) DeleteDeviceGroup(w http.ResponseWriter, r *http.Request) {
	user, ok := a.accessAdmin(w, r)
	if !ok {
		return
	}
	id, err := pathID(r)
	if err != nil {
		accessError(w, err)
		return
	}
	revision, err := strconv.ParseInt(r.FormValue("revision"), 10, 64)
	if err != nil || r.FormValue("confirm") != "1" {
		accessError(w, deviceaccess.ErrInvalid)
		return
	}
	if err = deviceaccess.DeleteGroup(r.Context(), a.DB, id, revision, user.ID); err != nil {
		accessError(w, err)
		return
	}
	http.Redirect(w, r, "/device-groups?result=deleted", 303)
}
func (a *App) UserDeviceAccessPage(w http.ResponseWriter, r *http.Request) {
	user, ok := a.accessAdmin(w, r)
	if !ok {
		return
	}
	id, err := pathID(r)
	if err != nil {
		accessError(w, err)
		return
	}
	var target auth.User
	if err = a.DB.QueryRowContext(r.Context(), "SELECT id,username,role FROM users WHERE id=?", id).Scan(&target.ID, &target.Username, &target.Role); err != nil {
		accessError(w, err)
		return
	}
	scope, err := deviceaccess.UserScope(r.Context(), a.DB, id)
	if err != nil {
		accessError(w, err)
		return
	}
	groups, err := deviceaccess.Groups(r.Context(), a.DB)
	if err != nil {
		accessError(w, err)
		return
	}
	checked := map[int64]bool{}
	for _, group := range scope.GroupIDs {
		checked[group] = true
	}
	data := userAccessData{User: user, Target: &target, Active: "users", CSRF: csrfToken(r), Scope: scope, Message: r.URL.Query().Get("result")}
	for _, group := range groups {
		data.Groups = append(data.Groups, groupChoice{Group: group, Checked: checked[group.ID]})
	}
	web.RenderPage(w, "user_access", data)
}
func (a *App) UpdateUserDeviceAccess(w http.ResponseWriter, r *http.Request) {
	user, ok := a.accessAdmin(w, r)
	if !ok {
		return
	}
	id, err := pathID(r)
	if err != nil {
		accessError(w, err)
		return
	}
	if err = r.ParseForm(); err != nil {
		accessError(w, deviceaccess.ErrInvalid)
		return
	}
	revision, err := strconv.ParseInt(r.FormValue("revision"), 10, 64)
	if err != nil {
		accessError(w, deviceaccess.ErrInvalid)
		return
	}
	groups, err := deviceaccess.IDs(r.Form["group"], 500)
	if err != nil {
		accessError(w, err)
		return
	}
	if err = deviceaccess.SetUserScope(r.Context(), a.DB, id, deviceaccess.Scope{Mode: r.FormValue("mode"), Revision: revision, GroupIDs: groups}, user.ID); err != nil {
		accessError(w, err)
		return
	}
	http.Redirect(w, r, "/users/"+strconv.FormatInt(id, 10)+"/access?result=saved", 303)
}
