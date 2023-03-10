import { useEffect, useState } from "react";
import reactLogo from "./assets/react.svg";
import "./index.css";
import "primereact/resources/themes/lara-light-indigo/theme.css";
import "primereact/resources/primereact.min.css";
import "primeicons/primeicons.css";
import { Accordion, AccordionTab } from "primereact/accordion";
import { Button } from "primereact/button";
import { Dialog } from "primereact/dialog";
import { InputText } from "primereact/inputtext";
import { ConfirmDialog } from "primereact/confirmdialog";
import { JsonToTable } from "react-json-to-table";
import { TabView, TabPanel } from "primereact/tabview";
import { Chart } from "primereact/chart";
import { ProgressSpinner } from "primereact/progressspinner";
import { Message } from "primereact/message";

async function getRunningContainers() {
  const response = await fetch("containers.json");
  const data = await response.json();
  console.log(data);
  return data;
}
const data_line_chart = {
  labels: ["January", "February", "March", "April", "May", "June", "July"],
  datasets: [
    {
      label: "Example Line Chart",
      data: [65, 59, 80, 81, 56, 55, 40],
      fill: false,
      borderColor: "#007be5",
    },
  ],
};

const options = {
  legend: {
    display: true,
  },
  scales: {
    yAxes: [
      {
        ticks: {
          beginAtZero: true,
        },
      },
    ],
  },
};

function App() {
  const HOST = "http://localhost";
  const VUl_PATH = "/vulnerable";
  const SAFE_PATH = "/safe";
  const [data, setData] = useState([]);
  const [type, setType] = useState("");
  const [number_, setNumber] = useState(0);
  const [message, setMessage] = useState("");
  const [currentItem, setCurrentItem] = useState({});
  const [loading, setLoading] = useState(false);

  const [visible, setVisible] = useState(false);
  const [vis, setVis] = useState(false);
  useEffect(() => {
    if (!Boolean(localStorage.getItem("CONT_CONFIRMED"))) setVisible(true);
    else {
      getRunningContainers().then((resp) => {
        console.log(resp);
        setData(resp);
      });
    }
    return () => {};
  }, []);

  const accept = () => {
    localStorage.setItem("CONT_CONFIRMED", "true");
  };
  const reject = () => {};
  const sendRequests = async () => {
    setVis(false);
    let PATH = VUl_PATH;
    if (type === "normal") {
      PATH = SAFE_PATH;
    }
    for (let i = 0; i < number_; i++) {
      setMessage(
        `sending  ${i}/${number_}th packet to ${
          currentItem.Ports.split(":::")[1].split("->")[0]
        }`
      );
      console.log(currentItem.Ports.split(":::")[1].split("->")[0]);
      await fetch(
        `${HOST}:${currentItem.Ports.split(":::")[1].split("->")[0]}${PATH}`
      );
    }
  };
  return (
    <>
      {loading && (
        <div className="w-screen h-screen fixed bg-white z-50 flex justify-center items-center">
          <div>
            <div className="flex justify-center">
              <ProgressSpinner />
            </div>

            <div className=" flex justify-center m-3">
              <Message text={message} />
            </div>
          </div>
        </div>
      )}

      <div>
        <ConfirmDialog
          visible={visible}
          onHide={() => setVisible(false)}
          message="Proceed to list all the containers?"
          header="Confirmation"
          icon="pi pi-exclamation-triangle"
          accept={accept}
          reject={reject}
        />
        <div className="flex  items-center mx-auto w-11/12  min-h-screen">
          <div className="  w-full">
            <Dialog
              header="Number of requests to be sent to: &nbsp;"
              visible={vis}
              style={{ width: "" }}
              onHide={() => setVis(false)}
            >
              <div className="w-full">
                <div className="flex justify-center">
                  <InputText
                    onChange={(e) => {
                      setNumber(Number(e.target.value));
                    }}
                    keyfilter="int"
                    placeholder="count"
                  />
                </div>
                <div className="text-xs my-4 flex justify-end">
                  <Button
                    onClick={() => {
                      setLoading(true);
                      sendRequests().then((r) => {
                        setLoading(false);
                      });
                    }}
                    label="Send"
                    severity="danger"
                    raised
                  />
                </div>
              </div>
            </Dialog>
            <div className="min-h-screen">
              <TabView>
                <TabPanel header="Running Containers">
                  <Accordion activeIndex={0}>
                    {data.map((item, index) => (
                      <AccordionTab header={item.Image}>
                        <div className="w-full overflow-x-scroll">
                          <JsonToTable json={item} />
                          <div className="my-8 flex justify-center">
                            <span className="p-buttonset ">
                              <Button
                                onClick={() => {
                                  setVis(true);
                                  setType("attack");
                                  setCurrentItem(item);
                                }}
                                className="bg-black"
                                label="Attack"
                                severity="danger"
                                icon="pi pi-exclamation-triangle"
                              />
                              <Button
                                onClick={() => {
                                  setVis(true);
                                  setType("normal");
                                  setCurrentItem(item);
                                }}
                                label="Benign"
                                icon="pi pi-check"
                                severity="success"
                              />
                              <Button label="Log" icon="pi pi-file" />
                            </span>
                          </div>
                        </div>
                      </AccordionTab>
                    ))}
                  </Accordion>
                </TabPanel>
                <TabPanel header="Insights">
                  <p className="m-0">
                    Sed ut perspiciatis unde omnis iste natus error sit
                    voluptatem accusantium doloremque laudantium, totam rem
                    aperiam, eaque ipsa quae ab illo inventore veritatis et
                    quasi architecto beatae vitae dicta sunt explicabo. Nemo
                    enim ipsam voluptatem quia voluptas sit aspernatur aut odit
                    aut fugit, sed quia consequuntur magni dolores eos qui
                    ratione voluptatem sequi nesciunt. Consectetur, adipisci
                    velit, sed quia non numquam eius modi.
                  </p>
                  <Chart type="line" data={data_line_chart} options={options} />
                  <p className="m-0">
                    Sed ut perspiciatis unde omnis iste natus error sit
                    voluptatem accusantium doloremque laudantium, totam rem
                    aperiam, eaque ipsa quae ab illo inventore veritatis et
                    quasi architecto beatae vitae dicta sunt explicabo. Nemo
                    enim ipsam voluptatem quia voluptas sit aspernatur aut odit
                    aut fugit, sed quia consequuntur magni dolores eos qui
                    ratione voluptatem sequi nesciunt. Consectetur, adipisci
                    velit, sed quia non numquam eius modi.
                  </p>
                  <Chart type="bar" data={data_line_chart} options={options} />
                </TabPanel>
                <TabPanel header="About">
                  <p className="m-0">
                    At vero eos et accusamus et iusto odio dignissimos ducimus
                    qui blanditiis praesentium voluptatum deleniti atque
                    corrupti quos dolores et quas molestias excepturi sint
                    occaecati cupiditate non provident, similique sunt in culpa
                    qui officia deserunt mollitia animi, id est laborum et
                    dolorum fuga. Et harum quidem rerum facilis est et expedita
                    distinctio. Nam libero tempore, cum soluta nobis est
                    eligendi optio cumque nihil impedit quo minus.
                  </p>
                </TabPanel>
              </TabView>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}

export default App;
