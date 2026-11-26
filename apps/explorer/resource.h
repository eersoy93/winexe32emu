/*
Copyright 2025-2026 Erdem Ersoy (eersoy93)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/* Explorer (My Computer) resource and command IDs */

#ifndef EXPLORER_RESOURCE_H
#define EXPLORER_RESOURCE_H

#define IDA_EXPLORER 100
#define IDD_PROPERTIES 101

/* Menu and toolbar commands */
#define IDM_OPEN       201
#define IDM_UP         202
#define IDM_REFRESH    203
#define IDM_EXIT       204
#define IDM_ABOUT      205
#define IDM_BACK       206
#define IDM_FORWARD    207
#define IDM_COMPUTER   208
#define IDM_NEWFOLDER  209
#define IDM_DELETE     210
#define IDM_RENAME     211
#define IDM_PROPERTIES 212
#define IDM_CUT        213
#define IDM_COPY       214
#define IDM_PASTE      215
#define IDM_SELECTALL  216
#define IDM_GO         217
#define IDM_ADDRESS    218
#define IDM_EXPAND     219
#define IDM_PURGE      220  /* Delete for good (Shift+Del) */
#define IDM_RESTORE    221  /* Recycle Bin: back where it was deleted from */
#define IDM_EMPTYBIN   222
#define IDM_GO_USER    223
#define IDM_GO_NETWORK 224
#define IDM_GO_BIN     225

/* Properties dialog: the name, label/value rows, the attributes */
#define IDC_PROP_NAME       300
#define IDC_PROP_LABEL1     301
#define IDC_PROP_LABEL2     302
#define IDC_PROP_LABEL3     303
#define IDC_PROP_LABEL4     304
#define IDC_PROP_LABEL5     305
#define IDC_PROP_LABEL6     306
#define IDC_PROP_LABEL7     307
#define IDC_PROP_VALUE1     311
#define IDC_PROP_VALUE2     312
#define IDC_PROP_VALUE3     313
#define IDC_PROP_VALUE4     314
#define IDC_PROP_VALUE5     315
#define IDC_PROP_VALUE6     316
#define IDC_PROP_VALUE7     317
#define IDC_PROP_ATTR_LABEL 320
#define IDC_PROP_READONLY   321
#define IDC_PROP_HIDDEN     322

#endif
